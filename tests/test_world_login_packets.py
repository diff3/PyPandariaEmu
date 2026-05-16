import json
import importlib
import struct
import sys
import types
from pathlib import Path
from types import SimpleNamespace

from DSL.modules.bitsHandler import BitInterPreter
from server.modules.interpretation.utils import dsl_decode


def _import_login_packets():
    stub_modules = {
        "server.modules.handlers.world.addons": {
            "addon_public_key_bytes": lambda: b"",
        },
        "server.modules.database.DatabaseConnection": {
            "DatabaseConnection": type("DatabaseConnection", (), {}),
        },
    }

    for module_name, attrs in stub_modules.items():
        module = types.ModuleType(module_name)
        for attr_name, value in attrs.items():
            setattr(module, attr_name, value)
        sys.modules[module_name] = module

    sys.modules.pop("server.modules.handlers.world.login.packets", None)
    sys.modules.pop("server.modules.handlers.world.login.flow", None)
    return importlib.import_module("server.modules.handlers.world.login.packets")


def _import_login_flow():
    _import_login_packets()
    sys.modules.pop("server.modules.handlers.world.login.flow", None)
    return importlib.import_module("server.modules.handlers.world.login.flow")


login_packets = _import_login_packets()
login_flow = _import_login_flow()
CAPTURE_DIR = Path(__file__).resolve().parents[2] / "data" / "pandaria548" / "captures" / "focus" / "debug"


def _capture_payload(name: str) -> bytes:
    return bytes.fromhex(json.loads((CAPTURE_DIR / name).read_text())["hex_compact"])


def test_known_spells_packet_uses_initial_spells_shape():
    ctx = SimpleNamespace(
        known_spells=[133, 116],
        race=1,
    )

    payload = login_packets.build_SMSG_SEND_KNOWN_SPELLS(ctx)

    initial_login_flag, byte_pos, bit_pos = BitInterPreter.read_bits(payload, 0, 0, 1)
    spell_count, byte_pos, bit_pos = BitInterPreter.read_bits(payload, byte_pos, bit_pos, 22)
    if bit_pos != 0:
        byte_pos += 1

    assert initial_login_flag == 0
    assert spell_count >= 2
    assert len(payload) == 3 + (int(spell_count) * 4)


def test_action_buttons_packet_uses_pandaria_button_count():
    ctx = SimpleNamespace(
        action_buttons=[0] * 132,
    )

    payload = login_packets.build_SMSG_UPDATE_ACTION_BUTTONS(ctx)

    assert len(payload) == 133
    assert payload[-1] == 0


def _decode_action_button_payload(payload: bytes) -> list[int]:
    buttons = [bytearray(8) for _ in range(132)]
    byte_pos = 0
    bit_pos = 0
    present = [{index: False for index in range(8)} for _ in range(132)]

    for byte_index in (4, 5, 3, 1, 6, 7, 0, 2):
        for button_index in range(132):
            bit_value, byte_pos, bit_pos = BitInterPreter.read_bits(payload, byte_pos, bit_pos, 1)
            present[button_index][byte_index] = bool(bit_value)

    if bit_pos != 0:
        byte_pos += 1

    for byte_index in (0, 1, 4, 6, 7, 2, 5, 3):
        for button_index in range(132):
            if not present[button_index][byte_index]:
                continue
            buttons[button_index][byte_index] = payload[byte_pos] ^ 0x01
            byte_pos += 1

    return [struct.unpack_from("<I", bytes(button), 0)[0] | struct.unpack_from("<I", bytes(button), 4)[0] for button in buttons]


def test_action_buttons_packet_writes_type_in_second_dword():
    ctx = SimpleNamespace(
        action_buttons=[((0x80 << 24) | 6948)] + ([0] * 131),
    )

    payload = login_packets.build_SMSG_UPDATE_ACTION_BUTTONS(ctx)
    buttons = _decode_action_button_payload(payload)

    assert buttons[0] == ((0x80 << 24) | 6948)


def test_action_buttons_packet_preserves_mount_type():
    ctx = SimpleNamespace(
        action_buttons=[((0x60 << 24) | 32235)] + ([0] * 131),
    )

    payload = login_packets.build_SMSG_UPDATE_ACTION_BUTTONS(ctx)
    buttons = _decode_action_button_payload(payload)

    assert buttons[0] == ((0x60 << 24) | 32235)


def test_pandaren_display_ids_do_not_fallback_to_blood_elf():
    assert login_packets._resolve_player_display_id(24, 0) == 38551
    assert login_packets._resolve_player_display_id(24, 1) == 38552
    assert login_packets._resolve_player_display_id(25, 0) == 38551
    assert login_packets._resolve_player_display_id(26, 1) == 38552


def test_pre_update_object_packets_include_action_buttons_again():
    assert "SMSG_UPDATE_TALENT_DATA" in login_flow.PRE_UPDATE_OBJECT_PACKETS
    assert "SMSG_UPDATE_ACTION_BUTTONS" in login_flow.PRE_UPDATE_OBJECT_PACKETS


def test_post_update_object_packets_include_empty_achievement_state():
    assert "SMSG_ALL_ACHIEVEMENT_DATA" in login_flow.POST_UPDATE_OBJECT_PACKETS


def test_all_achievement_data_packet_is_minimal_empty_state():
    payload = login_packets.build_SMSG_ALL_ACHIEVEMENT_DATA(SimpleNamespace())

    criteria_count, byte_pos, bit_pos = BitInterPreter.read_bits(payload, 0, 0, 19)
    achievement_count, _byte_pos, _bit_pos = BitInterPreter.read_bits(payload, byte_pos, bit_pos, 20)

    assert criteria_count == 0
    assert achievement_count == 0


def test_known_spells_packet_includes_common_for_alliance_race():
    ctx = SimpleNamespace(
        known_spells=[133, 116],
        race=1,
    )

    payload = login_packets.build_SMSG_SEND_KNOWN_SPELLS(ctx)
    _, byte_pos, bit_pos = BitInterPreter.read_bits(payload, 0, 0, 1)
    spell_count, byte_pos, bit_pos = BitInterPreter.read_bits(payload, byte_pos, bit_pos, 22)
    if bit_pos != 0:
        byte_pos += 1

    spells = [
        struct.unpack_from("<I", payload, byte_pos + (index * 4))[0]
        for index in range(int(spell_count))
    ]
    assert login_packets.SPELL_LANGUAGE_COMMON in spells
    assert login_packets.SPELL_LANGUAGE_ORCISH not in spells


def test_known_spells_packet_does_not_force_common_for_horde_race():
    ctx = SimpleNamespace(
        known_spells=[133, 116],
        race=2,
    )

    payload = login_packets.build_SMSG_SEND_KNOWN_SPELLS(ctx)
    _, byte_pos, bit_pos = BitInterPreter.read_bits(payload, 0, 0, 1)
    spell_count, byte_pos, bit_pos = BitInterPreter.read_bits(payload, byte_pos, bit_pos, 22)
    if bit_pos != 0:
        byte_pos += 1

    spells = [
        struct.unpack_from("<I", payload, byte_pos + (index * 4))[0]
        for index in range(int(spell_count))
    ]
    assert login_packets.SPELL_LANGUAGE_ORCISH in spells
    assert login_packets.SPELL_LANGUAGE_COMMON not in spells


def test_known_spells_packet_uses_journal_test_mount_subset():
    ctx = SimpleNamespace(
        known_spells=[133, 116],
        race=2,
    )

    payload = login_packets.build_SMSG_SEND_KNOWN_SPELLS(ctx)
    _, byte_pos, bit_pos = BitInterPreter.read_bits(payload, 0, 0, 1)
    spell_count, byte_pos, bit_pos = BitInterPreter.read_bits(payload, byte_pos, bit_pos, 22)
    if bit_pos != 0:
        byte_pos += 1

    spells = [
        struct.unpack_from("<I", payload, byte_pos + (index * 4))[0]
        for index in range(int(spell_count))
    ]

    assert 458 in spells
    assert 470 in spells
    assert 580 in spells
    assert 6648 in spells
    assert 68978 in spells
    assert 68992 in spells
    assert 32235 in spells
    assert 34769 in spells
    assert 61425 in spells
    assert 72286 in spells
    assert 89832 in spells
    assert 33388 in spells
    assert 33391 in spells
    assert 34090 in spells
    assert 34091 in spells
    assert 54197 in spells
    assert 115913 in spells
    assert 87840 not in spells
    assert 134735 not in spells


def test_update_object_0006_matches_pandaria548_value_update_shape():
    ctx = SimpleNamespace(
        exact_0006_map_id=1,
        exact_0006_guid=0x0000000700000003,
        display_id=15475,
        player_flags=32,
    )

    payload = login_packets.build_SMSG_UPDATE_OBJECT_1773613185_0006(ctx)
    decoded = dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True)
    update = decoded["updates"][0]

    assert len(payload) == 288
    assert update["update_type"] == 0
    assert update["guid"] == 0x0700000000000003
    assert update["mask_blocks"] == 63
    assert update["mask"]["set_bits"] == [6, 69, 70, 71, 162]
    assert update["fields"]["u32"] == [0, 15475, 15475, 0, 32]
    assert update["dynamic_mask_blocks"] == 1
    assert payload[-4:] == b"\x00\x00\x00\x00"


def test_update_object_0004_matches_pandaria548_value_update_shape():
    ctx = SimpleNamespace(
        exact_0004_map_id=1,
        exact_0004_guid=0x0000000700000003,
        display_id=15475,
        player_flags=0,
    )

    payload = login_packets.build_SMSG_UPDATE_OBJECT_1773613176_0004(ctx)
    decoded = dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True)
    update = decoded["updates"][0]

    assert len(payload) == 288
    assert update["update_type"] == 0
    assert update["guid"] == 0x0700000000000003
    assert update["mask_blocks"] == 63
    assert update["mask"]["set_bits"] == [6, 69, 70, 71, 162]
    assert update["fields"]["u32"] == [0, 15475, 15475, 0, 0]
    assert update["dynamic_mask_blocks"] == 1
    assert payload[-4:] == b"\x00\x00\x00\x00"


def test_update_object_1775665925_0004_matches_sniff_exactly():
    payload = login_packets.build_SMSG_UPDATE_OBJECT_1775665925_0004(SimpleNamespace(map_id=1))
    assert payload == _capture_payload("SMSG_UPDATE_OBJECT_1775665925_0004.json")


def test_update_object_1775665925_0005_matches_sniff_exactly():
    payload = login_packets.build_SMSG_UPDATE_OBJECT_1775665925_0005(SimpleNamespace(map_id=1))
    assert payload == _capture_payload("SMSG_UPDATE_OBJECT_1775665925_0005.json")


def test_update_object_1775665925_0006_matches_sniff_exactly():
    payload = login_packets.build_SMSG_UPDATE_OBJECT_1775665925_0006(SimpleNamespace(map_id=1))
    assert payload == _capture_payload("SMSG_UPDATE_OBJECT_1775665925_0006.json")


def test_update_object_1775665925_0009_matches_sniff_exactly():
    ctx = SimpleNamespace(
        map_id=1,
        exact_1775665925_0009_guid=0x0000000700000003,
        display_id=15475,
    )
    payload = login_packets.build_SMSG_UPDATE_OBJECT_1775665925_0009(ctx)
    assert payload == _capture_payload("SMSG_UPDATE_OBJECT_1775665925_0009.json")
