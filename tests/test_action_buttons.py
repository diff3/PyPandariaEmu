import importlib
import struct
import sys
import types
from types import SimpleNamespace

from DSL.modules.bitsHandler import BitWriter


def _import_misc_handlers():
    stub_modules = {
        "server.modules.database.DatabaseConnection": {
            "DatabaseConnection": type(
                "DatabaseConnection",
                (),
                {"save_character_action_button": staticmethod(lambda *args, **kwargs: True)},
            ),
        },
        "server.modules.handlers.world.login.packets": {
            "handle_CMSG_REQUEST_HOTFIX": lambda *args, **kwargs: None,
            "build_login_packet": lambda *args, **kwargs: b"",
        },
        "server.modules.handlers.world.account_data": {
            "DB_ACCOUNT_DATA_137_TYPES": (),
            "GLOBAL_ACCOUNT_DATA_STORAGE_TYPES": (),
            "GLOBAL_ACCOUNT_DATA_TYPES": (),
            "SEND_ACCOUNT_DATA_TO_CLIENT": True,
            "USE_DB_ACCOUNT_DATA_137": False,
            "account_data_mask_for_types": lambda *args, **kwargs: 0,
            "account_data_text_for_type": lambda *args, **kwargs: "",
            "account_data_times_list_for_types": lambda *args, **kwargs: [],
            "build_minimal_post_timesync_account_packets": lambda *args, **kwargs: [],
            "build_update_account_data_payload": lambda *args, **kwargs: b"",
            "decode_account_data_request_type": lambda *args, **kwargs: 0,
            "decode_account_data_update_payload": lambda *args, **kwargs: {},
            "flush_account_data_types_to_db": lambda *args, **kwargs: None,
            "is_global_account_data_type": lambda *args, **kwargs: False,
            "load_character_account_data": lambda *args, **kwargs: None,
            "load_global_account_data": lambda *args, **kwargs: None,
            "normalize_account_data_text": lambda *args, **kwargs: "",
            "persist_account_data_entry": lambda *args, **kwargs: None,
        },
        "server.modules.handlers.world.opcodes.login": {
            "_build_world_login_context": lambda session: SimpleNamespace(motd=""),
        },
        "server.modules.handlers.world.opcodes.movement": {
            "_save_current_position_like_command": lambda *args, **kwargs: True,
        },
        "server.modules.handlers.world.state.runtime": {
            "advance_global_time": lambda *args, **kwargs: None,
            "broadcast_player_remove": lambda *args, **kwargs: None,
            "broadcast_region_weather": lambda *args, **kwargs: None,
            "broadcast_system_message": lambda *args, **kwargs: None,
            "broadcast_world_time": lambda *args, **kwargs: None,
            "pack_wow_game_time": lambda *args, **kwargs: 0,
            "refresh_region_weather": lambda *args, **kwargs: None,
            "resolve_weather_type": lambda *args, **kwargs: 0,
        },
    }

    for module_name, attrs in stub_modules.items():
        module = types.ModuleType(module_name)
        for attr_name, value in attrs.items():
            setattr(module, attr_name, value)
        sys.modules[module_name] = module

    sys.modules.pop("server.modules.handlers.world.opcodes.misc", None)
    return importlib.import_module("server.modules.handlers.world.opcodes.misc")


misc_handlers = _import_misc_handlers()


def _build_set_action_button_payload(slot_id: int, action_id: int, action_type: int) -> bytes:
    raw = bytearray(
        struct.pack(
            "<II",
            int(action_id) & 0x00FFFFFF,
            (int(action_type) & 0xFF) << 24,
        )
    )
    bits = BitWriter()
    for index in (7, 0, 5, 2, 1, 6, 3, 4):
        bits.write_bits(1 if raw[index] else 0, 1)

    payload = bytearray([int(slot_id) & 0xFF])
    payload.extend(bits.getvalue())
    for index in (6, 7, 3, 5, 2, 1, 4, 0):
        if raw[index]:
            payload.append(raw[index] ^ 0x01)
    return bytes(payload)


def test_decode_set_action_button_payload_round_trip():
    payload = _build_set_action_button_payload(4, 6603, 0)

    slot_id, action_id, action_type = misc_handlers._decode_set_action_button_payload(payload)

    assert slot_id == 4
    assert action_id == 6603
    assert action_type == 0


def test_decode_set_action_button_payload_with_item_type_round_trip():
    payload = _build_set_action_button_payload(9, 6948, 0x80)

    slot_id, action_id, action_type = misc_handlers._decode_set_action_button_payload(payload)

    assert slot_id == 9
    assert action_id == 6948
    assert action_type == 0x80


def test_handle_set_action_button_updates_session_and_saves(monkeypatch):
    saved = {}

    monkeypatch.setattr(
        misc_handlers.DatabaseConnection,
        "save_character_action_button",
        lambda guid, button, action, type_, spec=0: saved.update(
            guid=guid,
            button=button,
            action=action,
            type_=type_,
            spec=spec,
        ) or True,
    )

    session = SimpleNamespace(char_guid=42, action_buttons=[0] * 132)
    ctx = SimpleNamespace(payload=_build_set_action_button_payload(7, 116, 0))

    code, responses = misc_handlers.handle_set_action_button(session, ctx)

    assert code == 0
    assert responses is None
    assert session.action_buttons[7] == 116
    assert saved == {}


def test_handle_set_action_button_clears_slot(monkeypatch):
    saved = {}

    monkeypatch.setattr(
        misc_handlers.DatabaseConnection,
        "save_character_action_button",
        lambda guid, button, action, type_, spec=0: saved.update(
            guid=guid,
            button=button,
            action=action,
            type_=type_,
            spec=spec,
        ) or True,
    )

    buttons = [0] * 132
    buttons[3] = 133
    session = SimpleNamespace(char_guid=99, action_buttons=buttons)
    ctx = SimpleNamespace(payload=_build_set_action_button_payload(3, 0, 0))

    code, responses = misc_handlers.handle_set_action_button(session, ctx)

    assert code == 0
    assert responses is None
    assert session.action_buttons[3] == 0
    assert saved == {}
