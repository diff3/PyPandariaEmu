from types import SimpleNamespace

from server.modules.game.guid import GameObjectGuid
from server.modules.handlers.world.opcodes import entities
from server.modules.handlers.world.teleport import gameobject_teleport
from server.modules.handlers.world.teleport.map_transfer import TeleportDestination
from server.modules.handlers.world.opcodes import movement
from server.modules.handlers.world.state.global_state import GlobalState
from server.session.world_session import WorldSession


def _session(char_guid=1001):
    state = GlobalState()
    session = WorldSession(
        char_guid=char_guid,
        player_guid=char_guid,
        world_guid=char_guid,
        realm_id=1,
        map_id=0,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        global_state=state,
    )
    session.send_response_log = []
    session.send_response = lambda responses: session.send_response_log.append(list(responses))
    state.sessions.add(session)
    return session


def _chair(**overrides):
    entry = {
        "guid": 50,
        "entry": 100,
        "map_id": 0,
        "x": 1.0,
        "y": 2.0,
        "z": 3.0,
        "orientation": 0.5,
        "type": entities.GAMEOBJECT_TYPE_CHAIR,
        "size": 1.0,
        "data0": 1,
        "data1": 1,
        "name": "Test Chair",
    }
    entry.update(overrides)
    return entry


def _goober(**overrides):
    entry = {
        "guid": 60,
        "entry": 200,
        "map_id": 0,
        "x": 1.0,
        "y": 2.0,
        "z": 0.0,
        "orientation": 0.5,
        "type": gameobject_teleport.GAMEOBJECT_TYPE_GOOBER,
        "flags": 0,
        "size": 1.0,
        "data10": 98765,
        "name": "Test Portal",
    }
    for index in range(24):
        entry.setdefault(f"data{index}", 0)
    entry["data10"] = 98765
    entry.update(overrides)
    return entry


def test_chair_use_moves_player_and_sets_chair_stand_state(monkeypatch):
    session = _session()
    chair = _chair()
    guid = GameObjectGuid.from_spawn_guid(chair["guid"], 1)
    monkeypatch.setattr(entities.DatabaseConnection, "get_gameobjects_near", lambda *args, **kwargs: [chair])
    monkeypatch.setattr(entities, "build_same_map_teleport_payload", lambda target: b"teleport")
    monkeypatch.setattr(
        entities,
        "build_single_u32_update_object_payload",
        lambda **fields: f"field={fields['field_index']} value={fields['value']}".encode(),
    )

    ctx = SimpleNamespace(payload=b"", decoded={"guid": guid})
    code, responses = entities.handle_gameobject_use(session, ctx)

    assert code == 0
    assert responses == [
        ("SMSG_MOVE_TELEPORT", b"teleport"),
        ("SMSG_UPDATE_OBJECT", b"field=76 value=5"),
    ]
    assert session.player_stand_state == 5
    assert session.current_chair is not None
    assert session.current_seat == 0
    assert (session.x, session.y, session.z, session.orientation) == (1.0, 2.0, 3.0, 0.5)


def test_gameobject_use_resolves_goober_spell_teleport(monkeypatch):
    session = _session()
    portal = _goober()
    guid = GameObjectGuid.from_spawn_guid(portal["guid"], 1)
    captured = {}

    monkeypatch.setattr(
        entities.DatabaseConnection,
        "get_gameobjects_near",
        lambda *args, **kwargs: [portal],
    )
    monkeypatch.setattr(gameobject_teleport.DatabaseConnection, "get_gameobject_teleport", lambda *args, **kwargs: None)
    monkeypatch.setattr(gameobject_teleport.DatabaseConnection, "get_gameobject_template", lambda entry: portal)
    monkeypatch.setattr(
        gameobject_teleport.DatabaseConnection,
        "get_spell_target_position",
        lambda spell_id, effect_index=0: {
            "id": spell_id,
            "effIndex": effect_index,
            "target_map": 1,
            "target_position_x": 10.0,
            "target_position_y": 20.0,
            "target_position_z": 30.0,
            "target_orientation": 7.0,
        },
    )

    def fake_transfer(target_session, destination, *, reason):
        captured["session"] = target_session
        captured["destination"] = destination
        captured["reason"] = reason
        return [("SMSG_NEW_WORLD", b"new-world")]

    monkeypatch.setattr(gameobject_teleport, "apply_map_transfer", fake_transfer)

    code, responses = entities.handle_gameobject_use(
        session,
        SimpleNamespace(name="CMSG_GAME_OBJ_USE", payload=b"", decoded={"guid": guid}),
    )

    assert code == 0
    assert responses == [("SMSG_NEW_WORLD", b"new-world")]
    assert captured["session"] is session
    assert captured["reason"] == "gameobject-teleport"
    assert captured["destination"] == TeleportDestination(
        map_id=1,
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=7.0 % (3.141592653589793 * 2.0),
        name="go:200:spell:98765",
    )


def test_gameobject_use_resolves_spellcaster_spell_teleport(monkeypatch):
    session = _session()
    portal = _goober(
        guid=61,
        entry=201,
        type=gameobject_teleport.GAMEOBJECT_TYPE_SPELLCASTER,
        data0=76543,
        data10=0,
        name="Spellcaster Portal",
    )
    guid = GameObjectGuid.from_spawn_guid(portal["guid"], 1)
    captured = {}

    monkeypatch.setattr(entities.DatabaseConnection, "get_gameobjects_near", lambda *args, **kwargs: [portal])
    monkeypatch.setattr(gameobject_teleport.DatabaseConnection, "get_gameobject_teleport", lambda *args, **kwargs: None)
    monkeypatch.setattr(gameobject_teleport.DatabaseConnection, "get_gameobject_template", lambda entry: portal)
    monkeypatch.setattr(
        gameobject_teleport.DatabaseConnection,
        "get_spell_target_position",
        lambda spell_id, effect_index=0: {
            "id": spell_id,
            "effIndex": effect_index,
            "target_map": 1,
            "target_position_x": 11.0,
            "target_position_y": 22.0,
            "target_position_z": 33.0,
            "target_orientation": 1.25,
        },
    )

    def fake_transfer(target_session, destination, *, reason):
        captured["destination"] = destination
        return [("SMSG_NEW_WORLD", b"spellcaster")]

    monkeypatch.setattr(gameobject_teleport, "apply_map_transfer", fake_transfer)

    code, responses = entities.handle_gameobject_use(
        session,
        SimpleNamespace(name="CMSG_GAME_OBJ_USE", payload=b"", decoded={"guid": guid}),
    )

    assert code == 0
    assert responses == [("SMSG_NEW_WORLD", b"spellcaster")]
    assert captured["destination"].name == "go:201:spell:76543"


def test_gameobject_use_resolves_triggered_spell_teleport(monkeypatch):
    portal = _goober(
        guid=63,
        entry=215457,
        type=gameobject_teleport.GAMEOBJECT_TYPE_SPELLCASTER,
        data0=130703,
        data10=0,
        name="Portal to Paw don Village",
    )
    requested_spells = []

    monkeypatch.setattr(
        gameobject_teleport.DatabaseConnection,
        "get_gameobject_teleport",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        gameobject_teleport.DatabaseConnection,
        "get_gameobject_template",
        lambda entry: portal,
    )
    monkeypatch.setattr(
        gameobject_teleport,
        "_teleport_spell_ids",
        lambda spell_id: (spell_id, 130702),
    )

    def target_position(spell_id, effect_index=0):
        requested_spells.append(spell_id)
        if spell_id != 130702:
            return None
        return {
            "id": 130702,
            "effIndex": effect_index,
            "target_map": 870,
            "target_position_x": -437.214,
            "target_position_y": -1907.87,
            "target_position_z": 53.5862,
            "target_orientation": 2.89331,
        }

    monkeypatch.setattr(
        gameobject_teleport.DatabaseConnection,
        "get_spell_target_position",
        target_position,
    )

    destination = gameobject_teleport.resolve_gameobject_teleport_destination(portal)

    assert requested_spells == [130703, 130702]
    assert destination == TeleportDestination(
        map_id=870,
        x=-437.214,
        y=-1907.87,
        z=53.5862,
        orientation=2.89331,
        name="go:215457:spell:130702",
    )


def test_gameobject_use_resolves_named_portal_via_game_tele_when_spell_target_is_missing(monkeypatch):
    session = _session()
    portal = _goober(
        guid=62,
        entry=202,
        type=gameobject_teleport.GAMEOBJECT_TYPE_SPELLCASTER,
        data0=17609,
        data10=0,
        name="Dalaran Portal to Orgrimmar",
    )
    guid = GameObjectGuid.from_spawn_guid(portal["guid"], 1)
    captured = {}

    monkeypatch.setattr(entities.DatabaseConnection, "get_gameobjects_near", lambda *args, **kwargs: [portal])
    monkeypatch.setattr(
        gameobject_teleport.DatabaseConnection,
        "get_gameobject_teleport",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        gameobject_teleport.DatabaseConnection,
        "get_gameobject_template",
        lambda entry: portal,
    )
    monkeypatch.setattr(
        gameobject_teleport.DatabaseConnection,
        "get_spell_target_position",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        gameobject_teleport,
        "find_teleport",
        lambda name: {
            "name": "Orgrimmar",
            "map": 1,
            "x": 1569.97,
            "y": -4397.41,
            "z": 16.0472,
            "o": 0.543025,
        } if name == "Orgrimmar" else None,
    )

    def fake_transfer(target_session, destination, *, reason):
        captured["destination"] = destination
        captured["reason"] = reason
        return [("SMSG_NEW_WORLD", b"game-tele")]

    monkeypatch.setattr(gameobject_teleport, "apply_map_transfer", fake_transfer)

    code, responses = entities.handle_gameobject_use(
        session,
        SimpleNamespace(name="CMSG_GAME_OBJ_USE", payload=b"", decoded={"guid": guid}),
    )

    assert code == 0
    assert responses == [("SMSG_NEW_WORLD", b"game-tele")]
    assert captured["reason"] == "gameobject-teleport"
    assert captured["destination"] == TeleportDestination(
        map_id=1,
        x=1569.97,
        y=-4397.41,
        z=16.0472,
        orientation=0.543025,
        name="go:202:game_tele:Orgrimmar",
    )


def test_gameobject_use_lookup_uses_portal_radius(monkeypatch):
    session = _session()
    portal = _goober(x=22.0, size=5.0)
    guid = GameObjectGuid.from_spawn_guid(portal["guid"], 1)
    captured = {}

    def fake_near(map_id, x, y, *, radius, limit):
        captured["radius"] = radius
        captured["limit"] = limit
        return [portal]

    monkeypatch.setattr(entities.DatabaseConnection, "get_gameobjects_near", fake_near)
    monkeypatch.setattr(gameobject_teleport.DatabaseConnection, "get_gameobject_teleport", lambda *args, **kwargs: None)
    monkeypatch.setattr(gameobject_teleport.DatabaseConnection, "get_gameobject_template", lambda entry: portal)
    monkeypatch.setattr(
        gameobject_teleport.DatabaseConnection,
        "get_spell_target_position",
        lambda *args, **kwargs: {
            "target_map": 1,
            "target_position_x": 10.0,
            "target_position_y": 20.0,
            "target_position_z": 30.0,
            "target_orientation": 0.0,
        },
    )
    monkeypatch.setattr(
        gameobject_teleport,
        "apply_map_transfer",
        lambda *args, **kwargs: [("SMSG_NEW_WORLD", b"far-origin")],
    )

    code, responses = entities.handle_gameobject_use(
        session,
        SimpleNamespace(name="CMSG_GAME_OBJ_USE", payload=b"", decoded={"guid": guid}),
    )

    assert code == 0
    assert responses == [("SMSG_NEW_WORLD", b"far-origin")]
    assert captured["radius"] == entities.GAMEOBJECT_USE_LOOKUP_RADIUS
    assert captured["limit"] == 180


def test_gameobject_teleport_allows_interaction_condition_flag(monkeypatch):
    session = _session()
    portal = _goober(flags=gameobject_teleport.GO_FLAG_INTERACT_COND)
    guid = GameObjectGuid.from_spawn_guid(portal["guid"], 1)

    monkeypatch.setattr(entities.DatabaseConnection, "get_gameobjects_near", lambda *args, **kwargs: [portal])
    monkeypatch.setattr(gameobject_teleport.DatabaseConnection, "get_gameobject_teleport", lambda *args, **kwargs: None)
    monkeypatch.setattr(gameobject_teleport.DatabaseConnection, "get_gameobject_template", lambda entry: portal)
    monkeypatch.setattr(
        gameobject_teleport.DatabaseConnection,
        "get_spell_target_position",
        lambda *args, **kwargs: {
            "target_map": 1,
            "target_position_x": 10.0,
            "target_position_y": 20.0,
            "target_position_z": 30.0,
            "target_orientation": 0.0,
        },
    )
    monkeypatch.setattr(
        gameobject_teleport,
        "apply_map_transfer",
        lambda *args, **kwargs: [("SMSG_NEW_WORLD", b"condition")],
    )

    code, responses = entities.handle_gameobject_use(
        session,
        SimpleNamespace(name="CMSG_GAME_OBJ_USE", payload=b"", decoded={"guid": guid}),
    )

    assert code == 0
    assert responses == [("SMSG_NEW_WORLD", b"condition")]


def test_gameobject_teleport_rejects_invalid_interaction_flags(monkeypatch):
    session = _session()
    portal = _goober(flags=gameobject_teleport.GO_FLAG_NOT_SELECTABLE)
    guid = GameObjectGuid.from_spawn_guid(portal["guid"], 1)

    monkeypatch.setattr(entities.DatabaseConnection, "get_gameobjects_near", lambda *args, **kwargs: [portal])
    monkeypatch.setattr(gameobject_teleport.DatabaseConnection, "get_gameobject_teleport", lambda *args, **kwargs: None)
    monkeypatch.setattr(gameobject_teleport.DatabaseConnection, "get_gameobject_template", lambda entry: portal)
    monkeypatch.setattr(
        gameobject_teleport.DatabaseConnection,
        "get_spell_target_position",
        lambda *args, **kwargs: {
            "target_map": 0,
            "target_position_x": 2.0,
            "target_position_y": 2.0,
            "target_position_z": 0.0,
            "target_orientation": 0.0,
        },
    )
    monkeypatch.setattr(
        gameobject_teleport,
        "apply_map_transfer",
        lambda *args, **kwargs: [("SMSG_MOVE_TELEPORT", b"bad")],
    )

    code, responses = entities.handle_gameobject_use(
        session,
        SimpleNamespace(name="CMSG_GAME_OBJ_USE", payload=b"", decoded={"guid": guid}),
    )

    assert code == 0
    assert responses is None


def test_chair_use_falls_back_to_nearest_chair_when_guid_payload_is_unknown(monkeypatch):
    session = _session()
    chair = _chair()
    monkeypatch.setattr(entities.DatabaseConnection, "get_gameobjects_near", lambda *args, **kwargs: [chair])
    monkeypatch.setattr(entities, "build_same_map_teleport_payload", lambda target: b"teleport")
    monkeypatch.setattr(entities, "build_single_u32_update_object_payload", lambda **fields: b"stand")

    code, responses = entities.handle_gameobject_use(
        session,
        SimpleNamespace(payload=bytes.fromhex("d889b41200"), decoded={}),
    )

    assert code == 0
    assert responses == [("SMSG_MOVE_TELEPORT", b"teleport"), ("SMSG_UPDATE_OBJECT", b"stand")]
    assert session.player_stand_state == 5
    assert session.current_seat == 0


def test_decoded_gameobject_miss_never_activates_a_different_nearby_portal(monkeypatch):
    session = _session()
    requested_guid = GameObjectGuid.from_spawn_guid(999, 1)
    nearby_portal = _goober(guid=60, entry=200)

    monkeypatch.setattr(
        entities.DatabaseConnection,
        "get_gameobjects_near",
        lambda *args, **kwargs: [nearby_portal],
    )
    monkeypatch.setattr(
        entities,
        "_find_nearest_teleport_gameobject",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("decoded target miss must not use a different portal")
        ),
    )

    code, responses = entities.handle_gameobject_use(
        session,
        SimpleNamespace(
            name="CMSG_GAME_OBJ_USE",
            payload=b"",
            decoded={"guid": requested_guid},
        ),
    )

    assert code == 0
    assert responses is None


def test_chair_multi_seat_blocks_occupied_seat(monkeypatch):
    alice = _session(1001)
    bob = _session(1002)
    bob.global_state = alice.global_state
    alice.global_state.sessions.add(bob)
    chair = _chair(data0=2, size=1.0)
    guid = GameObjectGuid.from_spawn_guid(chair["guid"], 1)
    monkeypatch.setattr(entities.DatabaseConnection, "get_gameobjects_near", lambda *args, **kwargs: [chair])
    monkeypatch.setattr(entities, "build_same_map_teleport_payload", lambda target: b"teleport")
    monkeypatch.setattr(entities, "build_single_u32_update_object_payload", lambda **fields: b"stand")

    entities.handle_gameobject_use(alice, SimpleNamespace(payload=b"", decoded={"guid": guid}))
    entities.handle_gameobject_use(bob, SimpleNamespace(payload=b"", decoded={"guid": guid}))

    assert alice.current_seat != bob.current_seat
    seats = alice.global_state.chair_occupancy[alice.current_chair]
    assert sorted(seats.values()) == [1001, 1002]


def test_facing_does_not_release_chair_seat(monkeypatch):
    session = _session()
    session.current_chair = 0x13000100000032
    session.current_seat = 0
    session.player_stand_state = 5
    session.global_state.chair_occupancy = {session.current_chair: {0: session.char_guid}}
    monkeypatch.setattr(movement, "build_single_u32_update_object_payload", lambda **fields: b"stand")

    movement._clear_dance_emote_state_on_move(session, "MSG_MOVE_SET_FACING")

    assert session.player_stand_state == 5
    assert session.current_chair == 0x13000100000032
    assert session.current_seat == 0


def test_movement_releases_chair_seat(monkeypatch):
    session = _session()
    session.current_chair = 0x13000100000032
    session.current_seat = 0
    session.player_stand_state = 5
    session.global_state.chair_occupancy = {session.current_chair: {0: session.char_guid}}
    monkeypatch.setattr(movement, "build_single_u32_update_object_payload", lambda **fields: b"stand")

    movement._clear_dance_emote_state_on_move(session, "MSG_MOVE_START_FORWARD")

    assert session.player_stand_state == 0
    assert session.current_chair is None
    assert session.current_seat is None
    assert session.global_state.chair_occupancy[0x13000100000032] == {}
