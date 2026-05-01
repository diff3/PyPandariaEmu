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
            "build_move_set_run_speed_payload": lambda session: b"",
            "build_move_set_flight_speed_payload": lambda session: b"",
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
        "SMSG_MOVE_SET_RUN_SPEED",
    ]
    assert session.is_mounted is False
    assert session.mount_spell is None
    assert session.active_mount_aura_spell_id is None


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
    assert session.can_fly is True
    assert session.is_flying is True
    assert session.movement_state.flags & spells_handlers._MOVEMENTFLAG_FLYING_CAPABILITY

    dismount_responses = spells_handlers.dismount(session)

    assert [opcode for opcode, _payload in mount_responses[:6]] == [
        "SMSG_AURA_UPDATE",
        "SMSG_UPDATE_OBJECT",
        "SMSG_SPLINE_MOVE_SET_FLYING",
        "SMSG_MOVE_SET_CAN_FLY",
        "SMSG_MOVE_SET_RUN_SPEED",
        "SMSG_MOVE_SET_FLIGHT_SPEED",
    ]
    assert mount_responses[2][1] == bytes.fromhex("1002")
    assert mount_responses[3][1] == b"can-fly-on"
    assert "SMSG_MOVE_SET_CAN_FLY" not in [opcode for opcode, _payload in duplicate_responses]
    assert [opcode for opcode, _payload in dismount_responses[:4]] == [
        "SMSG_AURA_UPDATE",
        "SMSG_DISMOUNT",
        "SMSG_MOVE_UNSET_CAN_FLY",
        "SMSG_SPLINE_MOVE_UNSET_FLYING",
    ]
    assert dismount_responses[2][1] == b"can-fly-off"
    assert dismount_responses[3][1] == bytes.fromhex("0202")
    assert session.can_fly is False
    assert session.is_flying is False
    assert not session.movement_state.flags & spells_handlers._MOVEMENTFLAG_FLYING_CAPABILITY


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
