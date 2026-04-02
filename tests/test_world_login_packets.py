import importlib
import struct
import sys
import types
from types import SimpleNamespace

from DSL.modules.bitsHandler import BitInterPreter


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

    assert len(payload) == 1189
    assert payload[-1] == 0


def test_action_buttons_packet_writes_type_in_second_dword():
    ctx = SimpleNamespace(
        action_buttons=[((0x80 << 24) | 6948)] + ([0] * 131),
    )

    payload = login_packets.build_SMSG_UPDATE_ACTION_BUTTONS(ctx)

    first_button = bytearray(8)
    group_start = 132
    for byte_index in (0, 1, 4, 6, 7, 2, 5, 3):
        first_button[byte_index] = payload[group_start] ^ 0x01
        group_start += 132

    action_id = struct.unpack_from("<I", bytes(first_button), 0)[0]
    action_type_word = struct.unpack_from("<I", bytes(first_button), 4)[0]
    assert action_id == 6948
    assert action_type_word == (0x80 << 24)


def test_pre_update_object_packets_include_action_buttons_again():
    assert "SMSG_UPDATE_TALENT_DATA" in login_flow.PRE_UPDATE_OBJECT_PACKETS
    assert "SMSG_UPDATE_ACTION_BUTTONS" in login_flow.PRE_UPDATE_OBJECT_PACKETS


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
    assert 668 in spells
