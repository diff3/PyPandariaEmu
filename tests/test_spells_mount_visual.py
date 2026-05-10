import importlib
import sys
import types
from types import SimpleNamespace


def _import_spells_handlers():
    stub_modules = {
        "server.modules.database.DatabaseConnection": {
            "DatabaseConnection": type("DatabaseConnection", (), {}),
        },
        "server.modules.handlers.world.login.context": {
            "WorldLoginContext": type(
                "WorldLoginContext",
                (),
                {"from_session": staticmethod(lambda session: SimpleNamespace())},
            ),
        },
        "server.modules.handlers.world.login.packets": {
            "_resolve_update_world_guid": lambda session: 0,
            "build_login_packet": lambda *args, **kwargs: b"",
        },
        "server.modules.handlers.world.chat.codec": {
            "encode_skyfire_messagechat_system_payload": lambda message: str(message).encode(),
        },
        "server.modules.handlers.world.bootstrap.replay": {
            "build_multi_u32_update_object_payload": lambda **fields: b"",
            "build_single_u32_update_object_payload": lambda **fields: b"",
            "make_update_object_response": lambda payload: ("SMSG_UPDATE_OBJECT", payload),
        },
        "server.modules.handlers.world.dispatcher": {
            "register": lambda *args, **kwargs: (lambda fn: fn),
        },
        "server.modules.handlers.world.opcodes.movement": {
            "build_move_set_can_fly_payload": lambda session, enabled: (
                b"can-fly-on" if enabled else b"can-fly-off"
            ),
            "build_move_set_speed_payload": lambda session, opcode_name, speed: str(opcode_name).encode(),
            "build_move_set_run_speed_payload": lambda session: b"",
            "build_move_set_flight_speed_payload": lambda session: b"",
            "resync_movement": lambda session: [],
        },
        "server.modules.handlers.world.state.runtime": {
            "_visible_guid_set": lambda session: getattr(session, "visible_guids", set()),
            "dispatch_responses_to_sessions": lambda targets, responses: None,
            "iter_in_world_sessions": lambda map_id=None: [],
        },
        "server.modules.handlers.world.mount.mount_service": {
            "ALL_MOUNT_SPELLS": set(),
            "get_mount_display_id": lambda spell_id: 0,
            "granted_mount_spells": lambda: [],
            "is_flying_mount_spell": lambda spell_id: False,
            "is_mount_spell": lambda spell_id: False,
        },
    }

    for module_name, attrs in stub_modules.items():
        module = types.ModuleType(module_name)
        for attr_name, value in attrs.items():
            setattr(module, attr_name, value)
        sys.modules[module_name] = module

    sys.modules.pop("server.modules.handlers.world.opcodes.spells", None)
    return importlib.import_module("server.modules.handlers.world.opcodes.spells")


def test_build_mount_visual_responses_uses_char_guid_and_only_mount_field(monkeypatch):
    spells_handlers = _import_spells_handlers()
    calls = []

    def fake_build_multi_u32_update_object_payload(**fields):
        calls.append(fields)
        return b"mount-packet"

    monkeypatch.setattr(
        spells_handlers,
        "build_multi_u32_update_object_payload",
        fake_build_multi_u32_update_object_payload,
    )

    session = SimpleNamespace(
        map_id=530,
        char_guid=3,
        world_guid=0x0003000100000003,
        unit_flags=0x00000020,
        mount_display_id=0,
    )

    responses = spells_handlers.build_mount_visual_responses(session, 2404)

    assert responses == [("SMSG_UPDATE_OBJECT", b"mount-packet")]
    assert calls == [
        {
            "map_id": 530,
            "guid": 3,
            "field_updates": [
                (61, 0x08000008),
                (69, 0),
                (70, 0),
                (71, 2404),
            ],
        }
    ]
    assert session.unit_flags == 0x08000020
    assert session.mount_display_id == 2404


def test_build_mount_visual_responses_clears_mount_display(monkeypatch):
    spells_handlers = _import_spells_handlers()
    calls = []

    def fake_build_multi_u32_update_object_payload(**fields):
        calls.append(fields)
        return b"dismount-packet"

    monkeypatch.setattr(
        spells_handlers,
        "build_multi_u32_update_object_payload",
        fake_build_multi_u32_update_object_payload,
    )

    session = SimpleNamespace(
        map_id=1,
        char_guid=3,
        world_guid=0x0003000100000003,
        unit_flags=0x08000020,
        mount_display_id=2404,
    )

    responses = spells_handlers.build_mount_visual_responses(session, 0)

    assert responses == [("SMSG_UPDATE_OBJECT", b"dismount-packet")]
    assert calls == [
        {
            "map_id": 1,
            "guid": 3,
            "field_updates": [
                (61, 0x00000008),
                (69, 0),
                (70, 0),
                (71, 0),
            ],
        }
    ]
    assert session.unit_flags == 0x00000020
    assert session.mount_display_id == 0


def test_apply_and_remove_mount_aura_track_runtime_state():
    spells_handlers = _import_spells_handlers()
    session = SimpleNamespace(
        active_mount_aura_spell_id=None,
        active_mount_aura_slot=0,
        mount_spell=59535,
    )

    apply_responses = spells_handlers.apply_mount_aura(session, 59535)
    remove_responses = spells_handlers.remove_mount_aura(session)

    assert apply_responses[0][0] == "SMSG_AURA_UPDATE"
    assert apply_responses[0][1][14:18] == (59535).to_bytes(4, "little")
    assert session.active_mount_aura_spell_id is None
    assert remove_responses == [("SMSG_AURA_UPDATE", bytes.fromhex("8000004400000602"))]


def test_apply_and_remove_fly_aura_track_runtime_state():
    spells_handlers = _import_spells_handlers()
    session = SimpleNamespace(
        active_fly_aura_spell_id=None,
        active_fly_aura_slot=1,
    )

    apply_responses = spells_handlers.apply_fly_aura(session)
    remove_responses = spells_handlers.remove_fly_aura(session)

    assert [opcode for opcode, _payload in apply_responses] == [
        "SMSG_AURA_UPDATE",
        "SMSG_AURA_UPDATE",
    ]
    assert apply_responses[0][1] == bytes.fromhex("80000044400001000000000B5A00F47D0000000100000000007943040602")
    assert apply_responses[1][1] == bytes.fromhex("8000004440000000000000035A00BD5101000003000000050602")
    assert session.active_fly_aura_spell_id is None
    assert remove_responses == [
        ("SMSG_AURA_UPDATE", bytes.fromhex("8000004400040602")),
        ("SMSG_AURA_UPDATE", bytes.fromhex("8000004400050602")),
    ]


def test_handle_mount_and_dismount_use_aura_visual_and_speed(monkeypatch):
    spells_handlers = _import_spells_handlers()
    monkeypatch.setattr(spells_handlers, "get_mount_display_id", lambda spell_id: 2404)
    monkeypatch.setattr(spells_handlers, "build_move_set_run_speed_payload", lambda session: b"run")
    monkeypatch.setattr(spells_handlers, "build_move_set_flight_speed_payload", lambda session: b"flight")
    monkeypatch.setattr(
        spells_handlers,
        "build_multi_u32_update_object_payload",
        lambda **fields: b"mount-update",
    )

    session = SimpleNamespace(
        map_id=1,
        char_guid=3,
        world_guid=0x0003000100000003,
        unit_flags=0x00000020,
        mount_display_id=0,
        mount_spell=None,
        is_mounted=False,
        run_speed=7.0,
        fly_speed=7.0,
        display_id=15475,
        native_display_id=15475,
        active_mount_aura_spell_id=None,
        active_mount_aura_slot=0,
        active_fly_aura_spell_id=None,
    )

    mount_responses = spells_handlers.handle_mount(session, 59535)
    assert [opcode for opcode, _payload in mount_responses[:4]] == [
        "SMSG_AURA_UPDATE",
        "SMSG_UPDATE_OBJECT",
        "SMSG_MOVE_SET_RUN_SPEED",
        "SMSG_MOVE_SET_FLIGHT_SPEED",
    ]
    assert session.is_mounted is True
    assert session.mount_spell == 59535
    assert session.active_mount_aura_spell_id == 59535

    dismount_responses = spells_handlers.dismount(session)
    assert [opcode for opcode, _payload in dismount_responses[:4]] == [
        "SMSG_AURA_UPDATE",
        "SMSG_DISMOUNT",
        "SMSG_UPDATE_OBJECT",
        "SMSG_MOVE_SET_WALK_SPEED",
    ]
    assert [opcode for opcode, _payload in dismount_responses[3:7]] == [
        "SMSG_MOVE_SET_WALK_SPEED",
        "SMSG_MOVE_SET_RUN_SPEED",
        "SMSG_MOVE_SET_SWIM_SPEED",
        "SMSG_MOVE_SET_FLIGHT_SPEED",
    ]
    assert session.is_mounted is False
    assert session.mount_spell is None
    assert session.active_mount_aura_spell_id is None


def test_handle_mount_persists_restorable_mount_state(monkeypatch):
    spells_handlers = _import_spells_handlers()
    saved = []

    monkeypatch.setattr(spells_handlers, "get_mount_display_id", lambda spell_id: 2404)
    def fake_build_mount_visual_responses(session, display_id):
        session.mount_display_id = int(display_id)
        return [("SMSG_UPDATE_OBJECT", b"mount")]

    monkeypatch.setattr(spells_handlers, "build_mount_visual_responses", fake_build_mount_visual_responses)
    monkeypatch.setattr(spells_handlers, "_broadcast_mount_visual_to_visible_peers", lambda session, display_id: None)
    monkeypatch.setattr(spells_handlers.DatabaseConnection, "save_character_mount_state", lambda *args, **kwargs: saved.append((args, kwargs)), raising=False)

    session = SimpleNamespace(
        char_guid=7,
        realm_id=1,
        mount_display_id=0,
        mount_spell=None,
        active_mount_aura_slot=0,
        run_speed=7.0,
        fly_speed=7.0,
    )

    spells_handlers.handle_mount(session, 59535)

    assert saved == [((7, 1), {"spell_id": 59535, "display_id": 2404})]


def test_dismount_clears_persisted_mount_state(monkeypatch):
    spells_handlers = _import_spells_handlers()
    cleared = []

    monkeypatch.setattr(spells_handlers, "send_dismount_update", lambda session: [("SMSG_DISMOUNT", b"off")])
    monkeypatch.setattr(spells_handlers.DatabaseConnection, "clear_character_mount_state", lambda *args: cleared.append(args), raising=False)

    session = SimpleNamespace(
        char_guid=7,
        realm_id=1,
        is_mounted=True,
        mount_spell=59535,
        mount_display_id=2404,
        unit_flags=spells_handlers._UNIT_FLAG_MOUNT,
        movement_state=None,
    )

    responses = spells_handlers.dismount(session)

    assert responses == [("SMSG_DISMOUNT", b"off")]
    assert cleared == [(7, 1)]


def test_restore_persisted_mount_state_prepares_login_state(monkeypatch):
    spells_handlers = _import_spells_handlers()

    monkeypatch.setattr(spells_handlers, "is_mount_spell", lambda spell_id: int(spell_id) == 59535)
    monkeypatch.setattr(spells_handlers, "get_mount_display_id", lambda spell_id: 2404)
    monkeypatch.setattr(
        spells_handlers.DatabaseConnection,
        "load_character_mount_state",
        lambda guid, realm: {"spell": 59535, "display_id": 2404},
        raising=False,
    )

    session = SimpleNamespace(
        unit_flags=0,
        mount_display_id=0,
        mount_spell=None,
        active_mount_aura_slot=0,
    )

    restored = spells_handlers.restore_persisted_mount_state(session, 7, 1)

    assert restored is True
    assert session.is_mounted is True
    assert session.mount_spell == 59535
    assert session.mount_display_id == 2404
    assert session.unit_flags & spells_handlers._UNIT_FLAG_MOUNT
    assert session.run_speed > 7.0


def test_login_mount_restore_sends_self_visual_aura_and_speed(monkeypatch):
    spells_handlers = _import_spells_handlers()

    monkeypatch.setattr(spells_handlers, "is_flying_mount_spell", lambda spell_id: False)
    monkeypatch.setattr(spells_handlers, "build_mount_visual_responses", lambda session, display_id: [
        ("SMSG_UPDATE_OBJECT", f"mount:{display_id}".encode("ascii"))
    ])
    monkeypatch.setattr(spells_handlers, "build_move_set_run_speed_payload", lambda session: b"run")
    monkeypatch.setattr(spells_handlers, "build_move_set_flight_speed_payload", lambda session: b"flight")

    session = SimpleNamespace(
        is_mounted=True,
        mount_spell=59535,
        mount_display_id=2404,
        active_mount_aura_slot=0,
        run_speed=14.0,
        fly_speed=14.0,
    )

    responses = spells_handlers.build_login_mount_restore_responses(session)

    assert [opcode for opcode, _payload in responses] == [
        "SMSG_UPDATE_OBJECT",
        "SMSG_AURA_UPDATE",
        "SMSG_MOVE_SET_RUN_SPEED",
        "SMSG_MOVE_SET_FLIGHT_SPEED",
    ]
    assert responses[0][1] == b"mount:2404"
    assert responses[2][1] == b"run"
    assert responses[3][1] == b"flight"


def test_login_flying_mount_restore_sends_flying_enable(monkeypatch):
    spells_handlers = _import_spells_handlers()

    monkeypatch.setattr(spells_handlers, "is_flying_mount_spell", lambda spell_id: True)
    monkeypatch.setattr(spells_handlers, "build_mount_visual_responses", lambda session, display_id: [
        ("SMSG_UPDATE_OBJECT", f"mount:{display_id}".encode("ascii"))
    ])
    monkeypatch.setattr(spells_handlers, "build_spline_move_flying_payload", lambda session: b"spline-fly")
    monkeypatch.setattr(spells_handlers, "build_move_set_can_fly_payload", lambda session, enabled: b"can-fly-on")
    monkeypatch.setattr(spells_handlers, "build_move_set_run_speed_payload", lambda session: b"run")
    monkeypatch.setattr(spells_handlers, "build_move_set_flight_speed_payload", lambda session: b"flight")
    monkeypatch.setattr(spells_handlers, "resync_movement", lambda session: [("SMSG_PLAYER_MOVE", b"move")])

    session = SimpleNamespace(
        is_mounted=True,
        mount_spell=72286,
        mount_display_id=31007,
        active_mount_aura_slot=0,
        active_fly_aura_spell_id=None,
        can_fly=False,
        is_flying=False,
        x=100.0,
        y=200.0,
        z=300.0,
        orientation=1.5,
        movement_state=SimpleNamespace(
            x=0.0,
            y=0.0,
            z=0.0,
            orientation=0.0,
            flags=0,
            is_ascending=False,
            is_descending=False,
            has_fall_data=True,
            fall_time=123,
            fall_vertical_speed=-1.0,
            fall_horizontal_speed=2.0,
            fall_sin_angle=0.5,
            fall_cos_angle=0.5,
        ),
        run_speed=14.0,
        fly_speed=14.0,
    )

    responses = spells_handlers.build_login_mount_restore_responses(session)

    assert [opcode for opcode, _payload in responses] == [
        "SMSG_UPDATE_OBJECT",
        "SMSG_AURA_UPDATE",
        "SMSG_AURA_UPDATE",
        "SMSG_AURA_UPDATE",
        "SMSG_SPLINE_MOVE_SET_FLYING",
        "SMSG_MOVE_SET_CAN_FLY",
        "SMSG_MOVE_SET_RUN_SPEED",
        "SMSG_MOVE_SET_FLIGHT_SPEED",
        "SMSG_PLAYER_MOVE",
    ]
    assert session.can_fly is True
    assert session.is_flying is True
    assert session.active_fly_aura_spell_id is not None
    assert session.fly_speed == session.run_speed * 3.2
    assert session.movement_state.x == 100.0
    assert session.movement_state.y == 200.0
    assert session.movement_state.z == 300.0
    assert session.movement_state.orientation == 1.5
    assert session.movement_state.has_fall_data is False
    assert session.movement_state.fall_vertical_speed == 0.0
    assert responses[4][1] == b"spline-fly"
    assert responses[5][1] == b"can-fly-on"
    assert responses[8][1] == b"move"


def test_flying_mount_enables_and_disables_flying_capability_once(monkeypatch):
    spells_handlers = _import_spells_handlers()
    monkeypatch.setattr(spells_handlers, "get_mount_display_id", lambda spell_id: 31007)
    monkeypatch.setattr(spells_handlers, "is_flying_mount_spell", lambda spell_id: True)
    monkeypatch.setattr(spells_handlers, "build_move_set_run_speed_payload", lambda session: b"run")
    monkeypatch.setattr(spells_handlers, "build_move_set_flight_speed_payload", lambda session: b"flight")
    monkeypatch.setattr(
        spells_handlers,
        "build_multi_u32_update_object_payload",
        lambda **fields: b"mount-update",
    )

    session = SimpleNamespace(
        map_id=1,
        char_guid=3,
        world_guid=0x0003000100000003,
        unit_flags=0x00000020,
        mount_display_id=0,
        mount_spell=None,
        is_mounted=False,
        can_fly=False,
        is_flying=False,
        movement_state=SimpleNamespace(
            flags=0,
            is_ascending=False,
            is_descending=False,
        ),
        run_speed=7.0,
        fly_speed=7.0,
        display_id=15475,
        native_display_id=15475,
        active_mount_aura_spell_id=None,
        active_mount_aura_slot=0,
    )

    mount_responses = spells_handlers.handle_mount(session, 72286)
    duplicate_responses = spells_handlers.handle_mount(session, 72286)
    assert session.can_fly is False
    assert session.is_flying is False
    assert not session.movement_state.flags & spells_handlers._MOVEMENTFLAG_FLYING_CAPABILITY

    assert [opcode for opcode, _payload in mount_responses[:8]] == [
        "SMSG_AURA_UPDATE",
        "SMSG_UPDATE_OBJECT",
        "SMSG_AURA_UPDATE",
        "SMSG_AURA_UPDATE",
        "SMSG_SPLINE_MOVE_SET_FLYING",
        "SMSG_MOVE_SET_CAN_FLY",
        "SMSG_MOVE_SET_RUN_SPEED",
        "SMSG_MOVE_SET_FLIGHT_SPEED",
    ]
    assert mount_responses[4][1] == bytes.fromhex("1002")
    assert mount_responses[5][1] == b"can-fly-on"
    assert [opcode for opcode, _payload in duplicate_responses[:6]] == [
        "SMSG_AURA_UPDATE",
        "SMSG_AURA_UPDATE",
        "SMSG_AURA_UPDATE",
        "SMSG_DISMOUNT",
        "SMSG_MOVE_UNSET_CAN_FLY",
        "SMSG_SPLINE_MOVE_UNSET_FLYING",
    ]
    assert duplicate_responses[4][1] == b"can-fly-off"
    assert duplicate_responses[5][1] == bytes.fromhex("0202")
    assert session.can_fly is False
    assert session.is_flying is False
    assert not session.movement_state.flags & spells_handlers._MOVEMENTFLAG_FLYING_CAPABILITY


def test_handle_cast_spell_mount_button_toggles_to_dismount(monkeypatch):
    spells_handlers = _import_spells_handlers()
    monkeypatch.setattr(spells_handlers, "is_mount_spell", lambda spell_id: True)
    monkeypatch.setattr(spells_handlers, "_extract_packet_spell_id", lambda _ctx: 59535)

    calls: list[str] = []

    def fake_handle_mount(session, spell_id):
        calls.append(f"mount:{spell_id}")
        return [("MOUNT", b"on")]

    def fake_dismount(session):
        calls.append("dismount")
        session.is_mounted = False
        session.mount_spell = None
        session.mount_display_id = 0
        return [("DISMOUNT", b"off")]

    monkeypatch.setattr(spells_handlers, "handle_mount", fake_handle_mount)
    monkeypatch.setattr(spells_handlers, "dismount", fake_dismount)

    session = SimpleNamespace(
        is_mounted=True,
        mount_spell=59535,
        mount_display_id=2404,
    )

    status, responses = spells_handlers.handle_cast_spell(
        session,
        SimpleNamespace(name="CMSG_CAST_SPELL", payload=b"", decoded={}),
    )

    assert status == 0
    assert responses == [("DISMOUNT", b"off")]
    assert calls == ["dismount"]


def test_cancel_mount_aura_suppresses_followup_cast_of_same_mount(monkeypatch):
    spells_handlers = _import_spells_handlers()
    monkeypatch.setattr(spells_handlers, "is_mount_spell", lambda spell_id: int(spell_id) == 59535)
    monkeypatch.setattr(spells_handlers, "_extract_packet_spell_id", lambda _ctx: 59535)

    calls: list[str] = []

    def fake_handle_mount(session, spell_id):
        calls.append(f"mount:{spell_id}")
        session.is_mounted = True
        session.mount_spell = int(spell_id)
        return [("MOUNT", b"on")]

    def fake_dismount(session):
        calls.append("dismount")
        session.is_mounted = False
        session.mount_spell = None
        session.mount_display_id = 0
        return [("DISMOUNT", b"off")]

    monkeypatch.setattr(spells_handlers, "handle_mount", fake_handle_mount)
    monkeypatch.setattr(spells_handlers, "dismount", fake_dismount)

    session = SimpleNamespace(
        is_mounted=True,
        mount_spell=59535,
        mount_display_id=2404,
    )

    cancel_status, cancel_responses = spells_handlers.handle_cancel_mount_aura(
        session,
        SimpleNamespace(name="CMSG_CANCEL_MOUNT_AURA", payload=b"", decoded={}),
    )
    cast_status, cast_responses = spells_handlers.handle_cast_spell(
        session,
        SimpleNamespace(name="CMSG_CAST_SPELL", payload=b"", decoded={}),
    )

    assert cancel_status == 0
    assert cancel_responses == [("DISMOUNT", b"off")]
    assert cast_status == 0
    assert cast_responses is None
    assert calls == ["dismount"]
    assert session.pending_mount_cancel_spell is None
    assert session.is_mounted is False


def test_dismount_clears_flying_runtime_state(monkeypatch):
    spells_handlers = _import_spells_handlers()
    monkeypatch.setattr(spells_handlers, "_restore_default_movement_speeds", lambda _player: None)
    monkeypatch.setattr(spells_handlers, "send_dismount_update", lambda _player: [("SMSG_DISMOUNT", b"off")])

    session = SimpleNamespace(
        is_mounted=True,
        mount_spell=72286,
        mount_display_id=31007,
        is_flying=True,
        unit_flags=spells_handlers._UNIT_FLAG_MOUNT,
        movement_state=SimpleNamespace(
            flags=(
                spells_handlers._MOVEMENTFLAG_CAN_FLY
                | spells_handlers._MOVEMENTFLAG_FLYING
                | spells_handlers._MOVEMENTFLAG_ASCENDING
                | spells_handlers._MOVEMENTFLAG_DESCENDING
            ),
            is_ascending=True,
            is_descending=True,
        ),
    )

    responses = spells_handlers.dismount(session)

    assert responses == [("SMSG_DISMOUNT", b"off")]
    assert session.is_mounted is False
    assert session.mount_spell is None
    assert session.mount_display_id == 0
    assert session.is_flying is False
    assert session.movement_state.is_ascending is False
    assert session.movement_state.is_descending is False
    assert session.movement_state.flags == 0


def test_mount_and_dismount_broadcast_visual_update_to_visible_peers(monkeypatch):
    spells_handlers = _import_spells_handlers()
    runtime_module = sys.modules["server.modules.handlers.world.state.runtime"]
    movement_module = sys.modules["server.modules.handlers.world.opcodes.movement"]
    peer = SimpleNamespace(visible_guids={3})
    hidden_peer = SimpleNamespace(visible_guids=set())
    dispatched = []
    payload_calls = []

    def fake_build_multi_u32_update_object_payload(**fields):
        payload_calls.append(fields)
        return f"mount-update-{len(payload_calls)}".encode()

    monkeypatch.setattr(spells_handlers, "get_mount_display_id", lambda spell_id: 2404)
    monkeypatch.setattr(spells_handlers, "build_move_set_run_speed_payload", lambda session: b"run")
    monkeypatch.setattr(spells_handlers, "build_move_set_flight_speed_payload", lambda session: b"flight")
    monkeypatch.setattr(movement_module, "build_smsg_player_move_payload", lambda session: b"move", raising=False)
    monkeypatch.setattr(
        spells_handlers,
        "build_multi_u32_update_object_payload",
        fake_build_multi_u32_update_object_payload,
    )
    monkeypatch.setattr(
        runtime_module,
        "iter_in_world_sessions",
        lambda map_id=None: [peer, hidden_peer],
    )
    monkeypatch.setattr(
        runtime_module,
        "dispatch_responses_to_sessions",
        lambda targets, responses: dispatched.append((list(targets), list(responses))),
    )

    session = SimpleNamespace(
        map_id=1,
        char_guid=3,
        world_guid=0x0003000100000003,
        unit_flags=0x00000020,
        mount_display_id=0,
        mount_spell=None,
        is_mounted=False,
        run_speed=7.0,
        fly_speed=7.0,
        display_id=15475,
        native_display_id=15475,
        active_mount_aura_spell_id=None,
        active_mount_aura_slot=0,
    )

    spells_handlers.handle_mount(session, 59535)
    spells_handlers.dismount(session)

    assert len(dispatched) == 2
    assert dispatched[0][0] == [peer]
    assert dispatched[0][1][0:3] == [
        ("SMSG_UPDATE_OBJECT", b"mount-update-2"),
        ("SMSG_MOVE_SET_RUN_SPEED", b"run"),
        ("SMSG_MOVE_SET_FLIGHT_SPEED", b"flight"),
    ]
    assert dispatched[0][1][3][0] == "SMSG_PLAYER_MOVE"
    assert dispatched[0][1][3][1]
    assert dispatched[1][0] == [peer]
    assert dispatched[1][1][0:3] == [
        ("SMSG_UPDATE_OBJECT", b"mount-update-4"),
        ("SMSG_MOVE_SET_RUN_SPEED", b"run"),
        ("SMSG_MOVE_SET_FLIGHT_SPEED", b"flight"),
    ]
    assert dispatched[1][1][3][0] == "SMSG_PLAYER_MOVE"
    assert dispatched[1][1][3][1]
    assert payload_calls[1] == {
        "map_id": 1,
        "guid": 3,
        "field_updates": [
            (61, 0x08000008),
            (69, 15475),
            (70, 15475),
            (71, 2404),
        ],
    }
    assert payload_calls[3] == {
        "map_id": 1,
        "guid": 3,
        "field_updates": [
            (61, 0x00000008),
            (69, 15475),
            (70, 15475),
            (71, 0),
        ],
    }


def test_initialize_session_language_state_sets_orcish_for_alliance():
    spells_handlers = _import_spells_handlers()
    session = SimpleNamespace(
        race=1,
        player_name="Alice",
        char_guid=3,
        language=0,
        known_languages_mask=0,
    )

    spells_handlers.initialize_session_language_state(session)

    assert session.language == 7
    assert session.current_language == 7
    assert session.known_languages_mask == (1 << 7)


def test_granted_language_spells_for_alliance_match_horde_default():
    spells_handlers = _import_spells_handlers()

    granted = spells_handlers.granted_language_spells_for_race(1)

    assert granted == [669]


def test_ensure_language_spells_known_normalizes_alliance_to_orcish_only():
    spells_handlers = _import_spells_handlers()
    session = SimpleNamespace(
        race=1,
        known_spells=[668, 29932, 133, 116],
    )

    spells_handlers.ensure_language_spells_known(session)

    assert sorted(session.known_spells) == [116, 133, 669]


def test_ensure_spell_known_keeps_runtime_language_spell_and_updates_language():
    spells_handlers = _import_spells_handlers()
    session = SimpleNamespace(
        race=2,
        language=0,
        known_spells=[133, 116],
        known_languages_mask=0,
        extra_language_spells=set(),
    )

    changed = spells_handlers.ensure_spell_known(session, 668)

    assert changed is True
    assert sorted(session.known_spells) == [116, 133, 668, 669]
    assert session.language == 7
    assert session.known_languages_mask == 0xFFFFFFFF
    assert session.extra_language_spells == {668}


def test_initialize_session_language_state_keeps_horde_on_orcish():
    spells_handlers = _import_spells_handlers()
    session = SimpleNamespace(
        race=2,
        player_name="Thrall",
        char_guid=4,
        language=0,
        known_languages_mask=0,
    )

    spells_handlers.initialize_session_language_state(session)

    assert session.language == 1
    assert session.current_language == 1
    assert session.known_languages_mask == (1 << 1)


def test_initialize_session_language_state_uses_orcish_for_neutral_pandaren():
    spells_handlers = _import_spells_handlers()
    session = SimpleNamespace(
        race=24,
        player_name="Pandaren",
        char_guid=24,
        language=0,
        known_languages_mask=0,
    )

    spells_handlers.initialize_session_language_state(session)

    assert session.language == 1
    assert session.current_language == 1
    assert session.known_languages_mask & (1 << 1)
    assert 669 in session.known_spells
    assert 108127 not in session.known_spells


def test_raw_known_spells_payload_loads():
    spells_handlers = _import_spells_handlers()

    payload = spells_handlers.load_raw_known_spells_payload()

    assert isinstance(payload, bytes)
    assert payload


def test_known_spells_flag_off_uses_server_builder(monkeypatch):
    spells_handlers = _import_spells_handlers()
    session = SimpleNamespace(known_spells=[], race=1)

    monkeypatch.setattr(spells_handlers, "USE_RAW_SNIFFED_KNOWN_SPELLS", False)
    monkeypatch.setattr(spells_handlers, "ensure_language_spells_known", lambda _session: None)
    monkeypatch.setattr(spells_handlers, "ensure_companion_pet_spells_known", lambda _session: None)
    monkeypatch.setattr(spells_handlers, "ensure_mount_spells_known", lambda _session: None)
    monkeypatch.setattr(
        spells_handlers,
        "build_known_spells_response",
        lambda _session: ("SMSG_SEND_KNOWN_SPELLS", b"server-built"),
    )

    responses = spells_handlers.build_active_mover_spell_sync_responses(session)

    assert responses == [("SMSG_SEND_KNOWN_SPELLS", b"server-built")]


def test_known_spells_flag_on_uses_raw_sniff(monkeypatch):
    spells_handlers = _import_spells_handlers()
    session = SimpleNamespace(known_spells=[], race=2)

    monkeypatch.setattr(spells_handlers, "USE_RAW_SNIFFED_KNOWN_SPELLS", True)
    monkeypatch.setattr(spells_handlers, "ensure_language_spells_known", lambda _session: None)
    monkeypatch.setattr(spells_handlers, "ensure_companion_pet_spells_known", lambda _session: None)
    monkeypatch.setattr(spells_handlers, "ensure_mount_spells_known", lambda _session: None)
    monkeypatch.setattr(
        spells_handlers,
        "load_raw_known_spells_payload",
        lambda: b"raw-known-spells",
    )

    responses = spells_handlers.build_active_mover_spell_sync_responses(session)

    assert responses == [("SMSG_SEND_KNOWN_SPELLS", b"raw-known-spells")]
