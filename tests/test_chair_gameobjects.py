from types import SimpleNamespace

from server.modules.game.guid import GameObjectGuid
from server.modules.handlers.world.opcodes import entities
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


def test_movement_releases_chair_seat(monkeypatch):
    session = _session()
    session.current_chair = 0x13000100000032
    session.current_seat = 0
    session.player_stand_state = 5
    session.global_state.chair_occupancy = {session.current_chair: {0: session.char_guid}}
    monkeypatch.setattr(movement, "build_single_u32_update_object_payload", lambda **fields: b"stand")

    movement._clear_dance_emote_state_on_move(session)

    assert session.player_stand_state == 0
    assert session.current_chair is None
    assert session.current_seat is None
    assert session.global_state.chair_occupancy[0x13000100000032] == {}
