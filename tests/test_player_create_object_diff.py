from __future__ import annotations

import hashlib
import importlib
import importlib.util
import inspect
from pathlib import Path
import pytest
import struct
import sys
from types import SimpleNamespace
import types

from server.modules.interpretation.utils import dsl_decode
from server.modules.handlers.world.bootstrap import playerobjects
from server.modules.handlers.world.bootstrap.playerobjects import (
    build_movement_block,
    build_skyfire_player_create_living_movement_block,
    build_full_player_create,
    build_update_mask,
    build_player_field_values,
    build_server_built_player_create,
    locate_mask_region,
    locate_field_region,
    extract_field_indices,
)


EXPECTED_PLAYER_CREATE_MOVEMENT_BLOCK = bytes.fromhex(
    "200000004009080000080000490000e040e00f494000009040c3f54840"
    "de507d465c57d93f00002040aef47d46000090400f000020400000e040"
    "711c9740fb536c41"
)

EXPECTED_SKYFIRE_PLAYER_CREATE_MOVEMENT_BLOCK = bytes.fromhex(
    "200000004009080000080000490000e040e00f494000002040c3f54840"
    "de507d465c57d93f00002040aef47d46000090400f711c97400000e040"
    "00009040fb536c41"
)


def _pack_msb_bits(values: list[tuple[int, int]]) -> bytes:
    output = bytearray()
    current = 0
    bit_count = 0
    for value, width in values:
        for bit_index in range(int(width) - 1, -1, -1):
            current = (current << 1) | ((int(value) >> bit_index) & 1)
            bit_count += 1
            if bit_count == 8:
                output.append(current)
                current = 0
                bit_count = 0
    if bit_count:
        output.append(current << (8 - bit_count))
    return bytes(output)


def _write_byte_seq(raw: bytes, index: int) -> bytes:
    return bytes((raw[index] ^ 0x01,)) if raw[index] else b""


def _skyfire_reference_player_create_living_movement(ctx: SimpleNamespace) -> bytes:
    """Independent SkyFire 5.4.8 Object.cpp CREATE_OBJECT living movement reference."""
    player_guid = int(
        getattr(ctx, "world_guid", 0)
        or getattr(ctx, "player_guid", 0)
        or getattr(ctx, "char_guid", 0)
        or getattr(ctx, "exact_0002_low_guid", 0)
        or 0
    )
    guid = player_guid.to_bytes(8, "little")
    transport_guid = int(getattr(ctx, "transport_guid", 0) or 0)
    has_transport = bool(getattr(ctx, "has_transport_data", False)) and transport_guid > 0
    trans_guid = transport_guid.to_bytes(8, "little") if has_transport else bytes(8)
    movement_flags = int(getattr(ctx, "movement_flags", 0) or 0) & 0xFFFFFFFF
    movement_flags2 = int(getattr(ctx, "movement_flags2", 0) or 0) & 0xFFFFFFFF
    timestamp = int(getattr(ctx, "timestamp", 0) or getattr(ctx, "movement_timestamp", 0) or 0)
    movement_counter = int(getattr(ctx, "movement_counter", 0) or 0)
    orientation = float(getattr(ctx, "orientation", 0.0) or 0.0)
    has_pitch = bool(getattr(ctx, "has_pitch", False)) or bool(
        movement_flags & (0x00100000 | 0x01000000)
    ) or bool(movement_flags2 & 0x10)
    has_fall_direction = bool(getattr(ctx, "has_fall_direction", False)) or bool(
        movement_flags & 0x00000800
    )
    fall_time = int(getattr(ctx, "fall_time", 0) or 0)
    has_fall_data = bool(has_fall_direction or fall_time)
    has_spline_elevation = bool(movement_flags & 0x02000000)
    time2 = int(getattr(ctx, "transport_time2", 0) or 0)
    time3 = int(getattr(ctx, "transport_time3", 0) or 0)

    bits = [
        (0, 1),  # UPDATEFLAG_UNK_400 / bit676
        (0, 1),  # anim kits
        (1, 1),  # living
        (0, 1),
        (0, 1),
        (0, 22),  # transport frames
        (0, 1),  # vehicle
        (0, 1),
        (0, 1),
        (0, 1),  # updateflag transport
        (0, 1),  # rotation
        (0, 1),
        (1, 1),  # self
        (0, 1),  # target
        (0, 1),
        (0, 1),
        (0, 1),
        (0, 1),
        (0, 1),  # go transport position
        (0, 1),
        (0, 1),  # stationary
        (1 if guid[2] else 0, 1),
        (0, 1),
        (0 if has_pitch else 1, 1),
        (1 if has_transport else 0, 1),
        (0, 1),
    ]
    if has_transport:
        bits.extend(
            [
                (1 if trans_guid[4] else 0, 1),
                (1 if trans_guid[2] else 0, 1),
                (1 if time3 else 0, 1),
                (1 if trans_guid[0] else 0, 1),
                (1 if trans_guid[1] else 0, 1),
                (1 if trans_guid[3] else 0, 1),
                (1 if trans_guid[6] else 0, 1),
                (1 if trans_guid[7] else 0, 1),
                (1 if time2 else 0, 1),
                (1 if trans_guid[5] else 0, 1),
            ]
        )
    bits.extend(
        [
            (0 if timestamp else 1, 1),
            (1 if guid[6] else 0, 1),
            (1 if guid[4] else 0, 1),
            (1 if guid[3] else 0, 1),
            (0 if abs(orientation) > 1e-6 else 1, 1),
            (0 if movement_counter else 1, 1),
            (1 if guid[5] else 0, 1),
            (0, 22),
            (0 if movement_flags else 1, 1),
            (0, 19),
            (1 if has_fall_data else 0, 1),
        ]
    )
    if movement_flags:
        bits.append((movement_flags & 0x3FFFFFFF, 30))
    bits.extend(
        [
            (0 if has_spline_elevation else 1, 1),
            (0, 1),  # no player spline in CREATE
            (0, 1),
            (1 if guid[0] else 0, 1),
            (1 if guid[7] else 0, 1),
            (1 if guid[1] else 0, 1),
            (0 if movement_flags2 else 1, 1),
        ]
    )
    if has_fall_data:
        bits.append((1 if has_fall_direction else 0, 1))
    if movement_flags2:
        bits.append((movement_flags2 & 0x1FFF, 13))

    output = bytearray(_pack_msb_bits(bits))
    if has_transport:
        output += _write_byte_seq(trans_guid, 7)
        output += struct.pack("<f", float(getattr(ctx, "transport_x", 0.0) or 0.0))
        if time3:
            output += struct.pack("<I", time3)
        output += struct.pack("<f", float(getattr(ctx, "transport_orientation", 0.0) or 0.0))
        output += struct.pack("<f", float(getattr(ctx, "transport_y", 0.0) or 0.0))
        output += _write_byte_seq(trans_guid, 4)
        output += _write_byte_seq(trans_guid, 1)
        output += _write_byte_seq(trans_guid, 3)
        output += struct.pack("<f", float(getattr(ctx, "transport_z", 0.0) or 0.0))
        output += _write_byte_seq(trans_guid, 5)
        if time2:
            output += struct.pack("<I", time2)
        output += _write_byte_seq(trans_guid, 0)
        output += struct.pack("<b", int(getattr(ctx, "transport_seat", -1)))
        output += _write_byte_seq(trans_guid, 6)
        output += _write_byte_seq(trans_guid, 2)
        output += struct.pack("<I", int(getattr(ctx, "transport_time", 0) or 0) & 0xFFFFFFFF)

    output += _write_byte_seq(guid, 4)
    output += struct.pack("<f", float(getattr(ctx, "fly_speed", 7.0) or 7.0))
    if movement_counter:
        output += struct.pack("<I", movement_counter)
    output += _write_byte_seq(guid, 2)
    if has_fall_data:
        if has_fall_direction:
            output += struct.pack("<f", float(getattr(ctx, "fall_xy_speed", 0.0) or 0.0))
            output += struct.pack("<f", float(getattr(ctx, "fall_cos_angle", 0.0) or 0.0))
            output += struct.pack("<f", float(getattr(ctx, "fall_sin_angle", 0.0) or 0.0))
        output += struct.pack("<I", fall_time)
        output += struct.pack("<f", float(getattr(ctx, "fall_zspeed", 0.0) or 0.0))
    output += _write_byte_seq(guid, 1)
    output += struct.pack("<f", float(getattr(ctx, "turn_speed", 3.1415939331054688) or 3.1415939331054688))
    if timestamp:
        output += struct.pack("<I", timestamp)
    output += struct.pack("<f", float(getattr(ctx, "run_back_speed", 2.5) or 2.5))
    if has_spline_elevation:
        output += struct.pack("<f", float(getattr(ctx, "spline_elevation", 0.0) or 0.0))
    output += _write_byte_seq(guid, 7)
    output += struct.pack("<f", float(getattr(ctx, "pitch_speed", 3.140000104904175) or 3.140000104904175))
    output += struct.pack("<f", float(getattr(ctx, "x", 0.0) or 0.0))
    if has_pitch:
        output += struct.pack("<f", float(getattr(ctx, "pitch", 0.0) or 0.0))
    if abs(orientation) > 1e-6:
        output += struct.pack("<f", orientation)
    output += struct.pack("<f", float(getattr(ctx, "walk_speed", 2.5) or 2.5))
    output += struct.pack("<f", float(getattr(ctx, "y", 0.0) or 0.0))
    output += struct.pack("<f", float(getattr(ctx, "fly_back_speed", 4.5) or 4.5))
    output += _write_byte_seq(guid, 3)
    output += _write_byte_seq(guid, 5)
    output += _write_byte_seq(guid, 6)
    output += _write_byte_seq(guid, 0)
    output += struct.pack("<f", float(getattr(ctx, "swim_back_speed", 4.722221851348877) or 4.722221851348877))
    output += struct.pack("<f", float(getattr(ctx, "run_speed", 7.0) or 7.0))
    output += struct.pack("<f", float(getattr(ctx, "swim_speed", 4.5) or 4.5))
    output += struct.pack("<f", float(getattr(ctx, "z", 0.0) or 0.0))
    return bytes(output)


def _import_login_packets_with_stubs():
    """Load packets.py directly with DB-related stubs for isolated tests."""
    db_module = types.ModuleType("server.modules.database.DatabaseConnection")
    db_module.DatabaseConnection = type(
        "DatabaseConnection",
        (),
        {
            "get_gameobjects_near": staticmethod(lambda *args, **kwargs: []),
            "get_creatures_near": staticmethod(lambda *args, **kwargs: []),
            "get_creature_template": staticmethod(lambda *args, **kwargs: {}),
        },
    )
    sys.modules["server.modules.database.DatabaseConnection"] = db_module

    module_name = "_test_login_packets_create_diff"
    module_path = (
        Path(__file__).resolve().parents[1]
        / "modules"
        / "handlers"
        / "world"
        / "login"
        / "packets.py"
    )
    sys.modules.pop(module_name, None)
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load packets.py spec for create diff test")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def build_create_payload(ctx: SimpleNamespace | None = None) -> bytes:
    """Build player CREATE_OBJECT through the native create path."""
    login_packets = _import_login_packets_with_stubs()
    ctx = ctx or SimpleNamespace(
        map_id=1,
        char_guid=14,
        player_guid=14,
        world_guid=14,
        exact_0002_low_guid=14,
        race=4,
        gender=1,
        x=16212.216796875,
        y=16253.169921875,
        z=14.770503044128418,
        orientation=1.6979784965515137,
        health=102,
        max_health=102,
        power_primary=40,
        max_power=40,
        level=1,
        faction_template=4,
        display_id=56,
        player_bytes=393479,
        player_bytes2=16777220,
        player_bytes3=1,
        max_level=90,
    )
    return login_packets.build_SMSG_UPDATE_OBJECT_1773613176_0002(ctx)


def test_self_player_create_uses_server_built_path_when_enabled(monkeypatch) -> None:
    login_packets = _import_login_packets_with_stubs()
    monkeypatch.setattr(login_packets, "build_server_built_player_create", lambda ctx: b"server-built")

    ctx = SimpleNamespace(map_id=1, char_guid=14)

    assert login_packets.build_SMSG_UPDATE_OBJECT_1773613176_0002(ctx) == b"server-built"


def test_remote_player_create_uses_native_path_when_server_built_enabled(monkeypatch) -> None:
    login_packets = _import_login_packets_with_stubs()

    captured_remote_flags = []

    def _build_native(ctx):
        captured_remote_flags.append(bool(getattr(ctx, "exact_0002_remote_player", False)))
        return b"server-built"

    monkeypatch.setattr(login_packets, "build_server_built_player_create", _build_native)

    ctx = SimpleNamespace(
        map_id=1,
        char_guid=14,
        exact_0002_remote_player=True,
    )

    assert login_packets.build_SMSG_UPDATE_OBJECT_1773613176_0002(ctx) == b"server-built"
    assert captured_remote_flags == [True]


def locate_update_field_region(payload: bytes) -> dict[str, int]:
    """Locate the field mask and field bytes inside the CREATE_OBJECT body."""
    return playerobjects.locate_update_field_region(payload)


def locate_field_region(payload: bytes) -> tuple[int, int]:
    """Return the start and end offsets for the CREATE_OBJECT field bytes."""
    region = locate_update_field_region(payload)
    return region["field_start"], region["field_end"]


def extract_field_indices(mask_bytes: bytes, mask_blocks: int) -> list[int]:
    """Expand the field mask into a flat list of enabled field indices."""
    indices: list[int] = []
    for word_index in range(mask_blocks):
        word = struct.unpack_from("<I", mask_bytes, word_index * 4)[0]
        for bit_index in range(32):
            if word & (1 << bit_index):
                indices.append(word_index * 32 + bit_index)
    return indices


def parse_field_values(field_bytes: bytes, field_indices: list[int]) -> dict[int, int]:
    """Decode packed uint32 field bytes into a field-indexed mapping."""
    values: dict[int, int] = {}
    offset = 0
    for field_index in field_indices:
        values[field_index] = struct.unpack_from("<I", field_bytes, offset)[0]
        offset += 4
    return values


def diff_field_values(ref_values: dict[int, int], srv_values: dict[int, int]) -> list[int]:
    """Return field indices whose decoded uint32 values differ."""
    differences: list[int] = []
    for field_index in ref_values:
        if ref_values[field_index] != srv_values.get(field_index):
            differences.append(field_index)
    return differences


def find_language_slot_candidates(fields: dict[int, int]) -> dict[int, int]:
    """Return field indices whose packed low-half looks like Common or Orcish."""
    candidates: dict[int, int] = {}
    for field_index, value in fields.items():
        low_half = int(value) & 0xFFFF
        if low_half in {98, 109}:
            print(f"[LANG SLOT CANDIDATE] {field_index} = {value}")
            candidates[field_index] = int(value)
    return candidates


def parse_update_fields(payload: bytes) -> dict[int, int]:
    """Parse uint32 update fields from the CREATE_OBJECT field block."""
    region = locate_update_field_region(payload)
    mask_bytes = payload[region["mask_start"] : region["mask_end"]]
    field_bytes = payload[region["field_start"] : region["field_end"]]
    field_values: dict[int, int] = {}
    field_offset = 0

    for word_index in range(region["mask_blocks"]):
        word_value = struct.unpack_from("<I", mask_bytes, word_index * 4)[0]
        for bit_index in range(32):
            if not (word_value & (1 << bit_index)):
                continue
            field_index = word_index * 32 + bit_index
            field_values[field_index] = struct.unpack_from("<I", field_bytes, field_offset)[0]
            field_offset += 4

    return field_values


def test_player_create_builds_native_payload() -> None:
    """The player CREATE_OBJECT path should always produce a native payload."""
    assert build_create_payload() is not None


def test_build_player_field_values_sets_alliance_primary_language_skill() -> None:
    """Alliance should build the native language/riding skill block."""
    ctx = SimpleNamespace(race=4, char_guid=14, world_guid=14)
    fields = build_player_field_values(ctx)

    assert fields[1153] == 49938530
    assert fields[1154] == 113
    assert fields[1281] == 24576300
    assert fields[1282] == 300
    assert fields[1409] == 24576300
    assert fields[1410] == 300
    assert fields[1155] == 0
    assert fields[1283] == 0
    assert fields[1411] == 0


def test_build_player_field_values_sets_horde_primary_language_skill() -> None:
    """Horde should build the native language/riding skill block."""
    ctx = SimpleNamespace(race=2, char_guid=14, world_guid=14)
    fields = build_player_field_values(ctx)

    assert fields[1153] == 49938541
    assert fields[1154] == 109
    assert fields[1281] == 24576300
    assert fields[1282] == 300
    assert fields[1409] == 24576300
    assert fields[1410] == 300
    assert fields[1155] == 0
    assert fields[1283] == 0
    assert fields[1411] == 0


def test_build_player_field_values_sets_coinage_from_login_context() -> None:
    """Login player create fields must include current copper for the bag UI."""
    ctx = SimpleNamespace(race=2, char_guid=14, world_guid=14, money=29959292)
    fields = build_player_field_values(ctx)

    assert fields[1149] == 29959292
    assert fields[1150] == 0


def test_identify_language_related_fields_from_alliance_horde_create_diff() -> None:
    """Diff Alliance vs Horde create fields and lock the language-related field indices."""
    alliance_payload = build_create_payload(
        ctx=SimpleNamespace(
            map_id=1,
            char_guid=14,
            player_guid=14,
            world_guid=14,
            exact_0002_low_guid=14,
            race=4,
            gender=1,
            faction="alliance",
            x=16212.216796875,
            y=16253.169921875,
            z=14.770503044128418,
            orientation=1.6979784965515137,
            health=102,
            max_health=102,
            power_primary=40,
            max_power=40,
            level=1,
            faction_template=4,
            display_id=56,
            player_bytes=393479,
            player_bytes2=16777220,
            player_bytes3=1,
            max_level=90,
        ),
    )
    horde_payload = build_create_payload(
        ctx=SimpleNamespace(
            map_id=1,
            char_guid=14,
            player_guid=14,
            world_guid=14,
            exact_0002_low_guid=14,
            race=2,
            gender=1,
            faction="horde",
            x=16212.216796875,
            y=16253.169921875,
            z=14.770503044128418,
            orientation=1.6979784965515137,
            health=102,
            max_health=102,
            power_primary=40,
            max_power=40,
            level=1,
            faction_template=2,
            display_id=52,
            player_bytes=393218,
            player_bytes2=16777220,
            player_bytes3=1,
            max_level=90,
        ),
    )

    region = locate_update_field_region(alliance_payload)
    field_indices = extract_field_indices(
        alliance_payload[region["mask_start"] : region["mask_end"]],
        region["mask_blocks"],
    )
    alliance_values = parse_field_values(
        alliance_payload[region["field_start"] : region["field_end"]],
        field_indices,
    )
    horde_values = parse_field_values(
        horde_payload[region["field_start"] : region["field_end"]],
        field_indices,
    )
    differences = diff_field_values(alliance_values, horde_values)
    alliance_candidates = find_language_slot_candidates(alliance_values)
    horde_candidates = find_language_slot_candidates(horde_values)

    print("fields that differ:", differences)
    print({index: (alliance_values[index], horde_values[index]) for index in differences})

    assert alliance_candidates == {1153: alliance_values[1153]}
    assert horde_candidates == {1153: horde_values[1153], 1154: horde_values[1154]}
    assert 1153 in differences
    assert 1154 in differences
    assert alliance_values[1153] == 49938530
    assert horde_values[1153] == 49938541
    assert alliance_values[1154] == 113
    assert horde_values[1154] == 109
    assert alliance_values[1281] == 24576300
    assert horde_values[1281] == 24576300
    assert alliance_values[1282] == 300
    assert horde_values[1282] == 300
    assert alliance_values[1409] == 24576300
    assert horde_values[1409] == 24576300
    assert alliance_values[1410] == 300
    assert horde_values[1410] == 300


def test_horde_player_create_keeps_level_field_in_final_payload() -> None:
    """Horde create should include field 55 and keep the runtime level value."""
    payload = build_create_payload(
        ctx=SimpleNamespace(
            map_id=1,
            char_guid=14,
            player_guid=14,
            world_guid=14,
            exact_0002_low_guid=14,
            race=2,
            gender=1,
            faction="horde",
            x=16212.216796875,
            y=16253.169921875,
            z=14.770503044128418,
            orientation=1.6979784965515137,
            health=102,
            max_health=102,
            power_primary=40,
            max_power=40,
            level=100,
            faction_template=2,
            display_id=52,
            player_bytes=393218,
            player_bytes2=16777220,
            player_bytes3=1,
            max_level=100,
        ),
    )
    region = locate_update_field_region(payload)
    field_indices = extract_field_indices(
        payload[region["mask_start"] : region["mask_end"]],
        region["mask_blocks"],
    )
    field_values = parse_field_values(
        payload[region["field_start"] : region["field_end"]],
        field_indices,
    )

    assert 55 in field_indices
    assert field_values[55] == 100


def test_horde_player_create_packs_unit_field_bytes_0_from_ctx() -> None:
    """Horde create should serialize UNIT_FIELD_BYTES_0 from runtime faction data."""
    payload = build_create_payload(
        ctx=SimpleNamespace(
            map_id=1,
            char_guid=13,
            player_guid=13,
            world_guid=13,
            exact_0002_low_guid=13,
            race=10,
            class_id=4,
            gender=1,
            faction="horde",
            x=16212.216796875,
            y=16253.169921875,
            z=14.770503044128418,
            orientation=1.6979784965515137,
            health=102,
            max_health=102,
            power_primary=40,
            max_power=40,
            level=90,
            faction_template=1610,
            display_id=52,
            player_bytes=393218,
            player_bytes2=16777220,
            player_bytes3=1,
            max_level=90,
        ),
    )
    region = locate_update_field_region(payload)
    field_indices = extract_field_indices(
        payload[region["mask_start"] : region["mask_end"]],
        region["mask_blocks"],
    )
    field_values = parse_field_values(
        payload[region["field_start"] : region["field_end"]],
        field_indices,
    )
    expected = 10 | (4 << 8) | (1 << 24)

    assert 30 in field_indices
    assert field_values[30] == expected


def test_player_create_preserves_mounted_runtime_fields() -> None:
    """Remote CREATE_OBJECT should include current mount state for already-mounted players."""
    payload = build_create_payload(
        ctx=SimpleNamespace(
            map_id=1,
            char_guid=13,
            player_guid=13,
            world_guid=13,
            exact_0002_low_guid=13,
            exact_0002_remote_player=True,
            race=10,
            class_id=4,
            gender=1,
            x=16212.216796875,
            y=16253.169921875,
            z=14.770503044128418,
            orientation=1.6979784965515137,
            health=102,
            max_health=102,
            power_primary=40,
            max_power=40,
            level=90,
            faction_template=1610,
            display_id=52,
            native_display_id=52,
            mount_display_id=2404,
            player_bytes=393218,
            player_bytes2=16777220,
            player_bytes3=1,
            max_level=90,
        ),
    )
    region = locate_update_field_region(payload)
    field_indices = extract_field_indices(
        payload[region["mask_start"] : region["mask_end"]],
        region["mask_blocks"],
    )
    field_values = parse_field_values(
        payload[region["field_start"] : region["field_end"]],
        field_indices,
    )

    assert 61 in field_indices
    assert 71 in field_indices
    assert field_values[61] == 0x08000008
    assert field_values[71] == 2404


def test_remote_player_create_clears_local_self_movement_flag() -> None:
    """Remote native CREATE_OBJECT should preserve the old remote flag distinction."""
    ctx = SimpleNamespace(
        map_id=1,
        char_guid=13,
        player_guid=13,
        world_guid=13,
        exact_0002_low_guid=13,
        race=10,
        class_id=4,
        gender=1,
        faction="horde",
        x=16212.216796875,
        y=16253.169921875,
        z=14.770503044128418,
        orientation=1.6979784965515137,
        health=102,
        max_health=102,
        power_primary=40,
        max_power=40,
        level=90,
        faction_template=1610,
        display_id=52,
        player_bytes=393218,
        player_bytes2=16777220,
        player_bytes3=1,
        max_level=90,
    )
    self_payload = build_create_payload(
        ctx=ctx,
    )
    remote_payload = build_create_payload(
        ctx=SimpleNamespace(**vars(ctx), exact_0002_remote_player=True),
    )

    assert self_payload[14] == 0x40
    assert remote_payload[14] == 0x00
    assert self_payload[:14] + b"\x00" + self_payload[15:] == remote_payload


def test_player_create_movement_block_keeps_stable_no_transport_login_layout() -> None:
    """Default player CREATE must keep the old no-transport login-safe layout."""
    ctx = SimpleNamespace(
        char_guid=14,
        player_guid=14,
        world_guid=14,
        exact_0002_low_guid=14,
        x=16212.216796875,
        y=16253.169921875,
        z=14.770503044128418,
        orientation=1.6979784965515137,
    )
    remote_ctx = SimpleNamespace(**vars(ctx), exact_0002_remote_player=True)

    assert build_movement_block(ctx) == EXPECTED_PLAYER_CREATE_MOVEMENT_BLOCK
    assert build_movement_block(remote_ctx) == EXPECTED_PLAYER_CREATE_MOVEMENT_BLOCK
    assert build_movement_block(ctx) != _skyfire_reference_player_create_living_movement(ctx)
    assert build_skyfire_player_create_living_movement_block(ctx) == (
        EXPECTED_SKYFIRE_PLAYER_CREATE_MOVEMENT_BLOCK
    )
    assert build_skyfire_player_create_living_movement_block(remote_ctx) == (
        EXPECTED_SKYFIRE_PLAYER_CREATE_MOVEMENT_BLOCK
    )
    assert build_skyfire_player_create_living_movement_block(ctx) == (
        _skyfire_reference_player_create_living_movement(ctx)
    )
    assert build_skyfire_player_create_living_movement_block(remote_ctx) == (
        _skyfire_reference_player_create_living_movement(remote_ctx)
    )


def test_player_create_transport_movement_block_matches_skyfire_reference() -> None:
    ctx = SimpleNamespace(
        char_guid=0x0807060504030210,
        player_guid=0x0807060504030210,
        world_guid=0x0807060504030210,
        exact_0002_low_guid=0x0807060504030210,
        x=-14334.94,
        y=1062.831,
        z=11.705,
        orientation=6.957354,
        has_transport_data=True,
        transport_guid=0x1FC0000000000007,
        transport_x=9.042,
        transport_y=5.740,
        transport_z=11.705,
        transport_orientation=2.377130,
        transport_time=114810,
        transport_time2=22,
        transport_time3=33,
        transport_seat=-1,
        movement_flags=0x00100000,
        movement_flags2=0x10,
        movement_counter=7,
        timestamp=123456,
        pitch=0.125,
        fall_time=55,
        fall_zspeed=-1.5,
        fall_xy_speed=2.5,
        fall_cos_angle=0.25,
        fall_sin_angle=0.75,
        spline_elevation=4.25,
    )

    actual = build_skyfire_player_create_living_movement_block(ctx)
    expected = _skyfire_reference_player_create_living_movement(ctx)

    assert actual == expected
    assert b"\x1E\x08\xAC\x10" in actual  # transport local X=9.042 follows guid[7].
    assert actual.index(struct.pack("<I", 114810)) > actual.index(struct.pack("<b", -1))


def test_player_create_transport_data_selects_skyfire_block_without_global_experiment(
    monkeypatch,
) -> None:
    ctx = SimpleNamespace(
        char_guid=16,
        player_guid=16,
        world_guid=16,
        exact_0002_low_guid=16,
        x=100.0,
        y=200.0,
        z=10.0,
        orientation=0.5,
        has_transport_data=True,
        transport_guid=0x1FC0000000000007,
        transport_x=2.0,
        transport_y=3.0,
        transport_z=4.0,
        transport_orientation=0.25,
        transport_time=1234,
        transport_time2=0,
        transport_time3=0,
        transport_seat=-1,
    )
    monkeypatch.setattr(
        playerobjects,
        "_experimental_player_create_living_movement_enabled",
        lambda: False,
    )

    assert build_movement_block(ctx) == build_skyfire_player_create_living_movement_block(ctx)
    assert build_movement_block(ctx) == _skyfire_reference_player_create_living_movement(ctx)


def test_player_create_living_movement_experiment_flag_selects_skyfire_path(monkeypatch) -> None:
    ctx = SimpleNamespace(
        char_guid=16,
        player_guid=16,
        world_guid=16,
        exact_0002_low_guid=16,
        x=100.0,
        y=200.0,
        z=10.0,
        orientation=0.5,
        has_transport_data=True,
        transport_guid=0x1FC0000000000007,
        transport_x=2.0,
        transport_y=3.0,
        transport_z=4.0,
        transport_orientation=0.25,
        transport_time=1234,
        transport_time2=0,
        transport_time3=0,
        transport_seat=-1,
    )

    monkeypatch.setattr(
        playerobjects,
        "_experimental_player_create_living_movement_enabled",
        lambda: False,
    )
    assert build_movement_block(ctx) == build_skyfire_player_create_living_movement_block(ctx)
    assert build_movement_block(ctx) == _skyfire_reference_player_create_living_movement(ctx)

    monkeypatch.setattr(
        playerobjects,
        "_experimental_player_create_living_movement_enabled",
        lambda: True,
    )
    assert build_movement_block(ctx) == build_skyfire_player_create_living_movement_block(ctx)
    assert build_movement_block(ctx) == _skyfire_reference_player_create_living_movement(ctx)


def test_player_create_transport_bootstrap_keeps_stable_no_transport_layout() -> None:
    ctx = SimpleNamespace(
        map_id=0,
        char_guid=16,
        player_guid=16,
        world_guid=16,
        exact_0002_low_guid=16,
        race=2,
        class_id=1,
        gender=0,
        x=100.0,
        y=200.0,
        z=10.0,
        orientation=0.5,
        health=100,
        max_health=100,
        power_primary=100,
        max_power=100,
        level=90,
        has_transport_data=False,
        transport_guid=0x1FC0000000000007,
        transport_x=2.0,
        transport_y=3.0,
        transport_z=4.0,
        transport_orientation=0.25,
        transport_time=1234,
        transport_time2=0,
        transport_time3=0,
        transport_seat=-1,
    )

    payload = build_full_player_create(ctx)
    assert payload is not None
    update = dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True)["updates"][0]

    assert payload[10:76] == build_movement_block(ctx)
    assert update["has_transport_data"] == 0
    assert "transport_guid_0_mask" not in update
    assert "transport_x" not in update


def test_server_built_create_mask_roundtrip_matches_field_values() -> None:
    """Ensure the CREATE_OBJECT mask is fully derived from field_values."""
    ctx = SimpleNamespace(
        map_id=1,
        char_guid=13,
        player_guid=13,
        world_guid=13,
        exact_0002_low_guid=13,
        race=10,
        class_id=4,
        gender=1,
        faction="horde",
        x=16212.216796875,
        y=16253.169921875,
        z=14.770503044128418,
        orientation=1.6979784965515137,
        health=102,
        max_health=102,
        power_primary=40,
        max_power=40,
        level=90,
        faction_template=1610,
        display_id=52,
        player_bytes=393218,
        player_bytes2=16777220,
        player_bytes3=1,
        max_level=90,
    )
    field_values = build_player_field_values(ctx)
    mask_bytes, mask_words = build_update_mask(field_values)
    field_indices = extract_field_indices(mask_bytes, mask_words)
    payload = build_create_payload(
        ctx=ctx,
    )
    parsed_fields = parse_update_fields(payload)

    assert sum(byte.bit_count() for byte in mask_bytes) == len(field_values)
    assert set(field_indices) == set(field_values)
    assert len(parsed_fields) == len(field_values)
    assert set(parsed_fields) == set(field_values)


def test_player_create_named_defaults_are_owned_without_packet_change() -> None:
    """Migrated 0002 defaults should remain byte-stable outside reference ownership."""
    ctx = SimpleNamespace(
        map_id=1,
        char_guid=13,
        player_guid=13,
        world_guid=13,
        exact_0002_low_guid=13,
        race=10,
        class_id=4,
        gender=1,
        faction="horde",
        x=16212.216796875,
        y=16253.169921875,
        z=14.770503044128418,
        orientation=1.6979784965515137,
        health=102,
        max_health=102,
        power_primary=40,
        max_power=40,
        level=90,
        faction_template=1610,
        display_id=52,
        player_bytes=393218,
        player_bytes2=16777220,
        player_bytes3=1,
        max_level=90,
    )
    expected_fields = {
        36: 100,
        41: 1000,
        42: 100,
        43: 100,
        45: 1066639324,
        50: 1042536202,
        154: 1065353216,
        90: 18,
        91: 25,
        92: 19,
        93: 22,
        94: 22,
        126: 40,
        127: 83,
        72: 1074341010,
        73: 1078535314,
        129: 8,
        137: 1065353216,
        138: 1073741824,
        1610: 1095173714,
        1612: 1093282693,
        1613: 1093282693,
        1614: 1093282693,
        1616: 1084224438,
        1617: 1084224438,
        1618: 1084224438,
        1619: 1084224438,
        1620: 1084224438,
        1621: 1084224438,
        1622: 30,
        1624: 1090519040,
        1829: 12,
        1830: 12,
        1831: 12,
        1832: 12,
        1833: 12,
        1834: 12,
        1849: 12,
        1648: 8,
        1827: 65,
    }

    field_values = build_player_field_values(ctx)
    payload = build_create_payload(
        ctx=ctx,
    )
    parsed_fields = parse_update_fields(payload)

    assert len(payload) == 826
    assert hashlib.sha256(payload).hexdigest() == (
        "271121547417fb246f08a4f764a3810b0bfafde0b668c1e556559fc5fa23b1fd"
    )
    assert {field: field_values[field] for field in expected_fields} == expected_fields
    assert {field: parsed_fields[field] for field in expected_fields} == expected_fields
    assert not (set(expected_fields) & set(playerobjects._PLAYER_CREATE_REFERENCE_DERIVED_FIELDS))


def test_server_built_create_runtime_path_is_single_source_of_truth() -> None:
    """Runtime CREATE_OBJECT must use only the server-built path."""
    ctx = SimpleNamespace(
        map_id=1,
        char_guid=14,
        player_guid=14,
        world_guid=14,
        exact_0002_low_guid=14,
        race=4,
        class_id=11,
        gender=1,
        faction="alliance",
        x=16212.216796875,
        y=16253.169921875,
        z=14.770503044128418,
        orientation=1.6979784965515137,
        health=102,
        max_health=102,
        power_primary=40,
        max_power=40,
        level=1,
        faction_template=4,
        display_id=56,
        player_bytes=393479,
        player_bytes2=16777220,
        player_bytes3=1,
        max_level=90,
    )

    runtime_payload = build_server_built_player_create(ctx)
    direct_payload = build_full_player_create(ctx)
    source = inspect.getsource(build_server_built_player_create)

    assert runtime_payload is not None
    assert direct_payload is not None
    assert runtime_payload == direct_payload
    assert "template" not in source.lower()
    assert "replay" not in source.lower()
    assert not hasattr(importlib.import_module("server.modules.handlers.world.bootstrap.playerobjects"), "_PLAYER_CREATE_TEMPLATE_PATH")
    assert not hasattr(importlib.import_module("server.modules.handlers.world.bootstrap.playerobjects"), "_load_player_create_template_payload")
    assert not hasattr(importlib.import_module("server.modules.handlers.world.bootstrap.playerobjects"), "build_server_built_player_create_from_template")


@pytest.mark.parametrize(
    "race,faction,faction_template",
    [
        (4, "alliance", 4),
        (2, "horde", 2),
    ],
)
def test_server_built_player_create_keeps_level_field_in_mask_for_login_bootstrap(
    race,
    faction,
    faction_template,
):
    ctx = SimpleNamespace(
        map_id=1,
        char_guid=17,
        player_guid=17,
        world_guid=17,
        exact_0002_low_guid=17,
        race=race,
        class_id=11,
        gender=1,
        faction=faction,
        x=16212.216796875,
        y=16253.169921875,
        z=14.770503044128418,
        orientation=1.6979784965515137,
        health=102,
        max_health=102,
        power_primary=40,
        max_power=40,
        level=90,
        faction_template=faction_template,
        display_id=56,
        player_bytes=393479,
        player_bytes2=16777220,
        player_bytes3=1,
        max_level=90,
    )

    payload = build_server_built_player_create(ctx)

    assert payload is not None
    mask_start, mask_end, mask_blocks = locate_mask_region(payload)
    field_indices = extract_field_indices(payload[mask_start:mask_end], mask_blocks)
    field_start, field_end = locate_field_region(payload)

    assert 55 in field_indices
    level_offset = field_indices.index(55) * 4
    assert struct.unpack_from("<I", payload[field_start:field_end], level_offset)[0] == 90


@pytest.mark.parametrize("guid", [30, 255, 256, 512, 65536])
def test_server_built_player_create_locates_mask_from_packed_guid_length(guid):
    ctx = SimpleNamespace(
        map_id=0,
        char_guid=guid,
        player_guid=guid,
        world_guid=guid,
        race=4,
        class_id=11,
        gender=1,
        faction="alliance",
        x=16212.216796875,
        y=16253.169921875,
        z=14.770503044128418,
        orientation=1.6979784965515137,
        health=102,
        max_health=102,
        power_primary=40,
        max_power=40,
        level=90,
        faction_template=4,
        display_id=56,
        player_bytes=393479,
        player_bytes2=16777220,
        player_bytes3=1,
        max_level=90,
    )

    payload = build_server_built_player_create(ctx)

    assert payload is not None
    mask_start, mask_end, mask_blocks = locate_mask_region(payload)
    field_indices = extract_field_indices(payload[mask_start:mask_end], mask_blocks)
    field_start, field_end = locate_field_region(payload)

    assert 55 in field_indices
    level_offset = field_indices.index(55) * 4
    assert struct.unpack_from("<I", payload[field_start:field_end], level_offset)[0] == 90
