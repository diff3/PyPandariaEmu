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
            "build_move_set_run_speed_payload": lambda session: b"",
        },
        "server.modules.handlers.world.mount.mount_service": {
            "ALL_MOUNT_SPELLS": set(),
            "get_mount_display_id": lambda spell_id: 0,
            "granted_mount_spells": lambda: [],
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
                (0x60, 0x08000020),
                (106, 2404),
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
                (0x60, 0x00000020),
                (106, 0),
            ],
        }
    ]
    assert session.unit_flags == 0x00000020
    assert session.mount_display_id == 0


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

    assert session.language == 1
    assert session.known_languages_mask == 0xFFFFFFFF


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
    assert session.known_languages_mask == 0xFFFFFFFF
