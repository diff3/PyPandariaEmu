from __future__ import annotations

import importlib
import importlib.util
import inspect
from pathlib import Path
import pytest
import struct
import sys
from types import SimpleNamespace
import types

from shared.Logger import Logger
from server.modules.handlers.world.bootstrap.playerobjects import (
    build_full_player_create,
    build_movement_block,
    build_update_mask,
    build_player_field_values,
    build_server_built_player_create,
    locate_mask_region,
    locate_field_region,
    extract_field_indices,
)


REFERENCE_CREATE_CAPTURE_NAME = "SMSG_UPDATE_OBJECT_1776451639_0458.json"
REFERENCE_CREATE_CAPTURE_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "skyfire548"
    / "captures"
    / "focus"
    / "debug"
    / REFERENCE_CREATE_CAPTURE_NAME
)
CURRENT_CREATE_BUILDER_IS_SERVER_BUILT = False


def _import_replay_with_stubs():
    """Import replay with lightweight stubs so load_sniff_payload stays reusable."""
    packets_module = types.ModuleType("server.modules.handlers.world.login.packets")
    packets_module.build_login_packet = lambda *args, **kwargs: b""
    sys.modules["server.modules.handlers.world.login.packets"] = packets_module

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

    runtime_module = types.ModuleType("server.session.runtime")
    runtime_module.session = SimpleNamespace()
    sys.modules["server.session.runtime"] = runtime_module

    sys.modules.pop("server.modules.handlers.world.bootstrap.replay", None)
    return importlib.import_module("server.modules.handlers.world.bootstrap.replay")


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


def load_reference_payload() -> bytes:
    """Load the reference player CREATE_OBJECT payload from the SkyFire capture."""
    replay = _import_replay_with_stubs()
    return replay.load_sniff_payload(REFERENCE_CREATE_CAPTURE_PATH)


def build_server_payload() -> bytes:
    """Build the current player CREATE_OBJECT payload under test."""
    return build_create_payload(use_server_built_player_create=False)


def build_create_payload(
    *,
    use_server_built_player_create: bool,
    use_server_built_player_create_direct: bool = False,
    ctx: SimpleNamespace | None = None,
) -> bytes:
    """Build player CREATE_OBJECT with an explicit create-path flag."""
    login_packets = _import_login_packets_with_stubs()
    login_packets.USE_SERVER_BUILT_PLAYER_CREATE = use_server_built_player_create
    login_packets.USE_SERVER_BUILT_PLAYER_CREATE_DIRECT = use_server_built_player_create_direct
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
    login_packets.USE_SERVER_BUILT_PLAYER_CREATE = True
    monkeypatch.setattr(login_packets, "build_server_built_player_create", lambda ctx: b"server-built")
    monkeypatch.setattr(
        login_packets,
        "_build_barncastle_update_object_1773613176_0002_payload",
        lambda ctx: b"replay-built",
    )

    ctx = SimpleNamespace(map_id=1, char_guid=14)

    assert login_packets.build_SMSG_UPDATE_OBJECT_1773613176_0002(ctx) == b"server-built"


def test_remote_player_create_uses_replay_path_when_server_built_enabled(monkeypatch) -> None:
    login_packets = _import_login_packets_with_stubs()
    login_packets.USE_SERVER_BUILT_PLAYER_CREATE = True
    monkeypatch.setattr(login_packets, "build_server_built_player_create", lambda ctx: b"server-built")
    monkeypatch.setattr(
        login_packets,
        "_build_barncastle_update_object_1773613176_0002_payload",
        lambda ctx: b"replay-built-payload",
    )
    monkeypatch.setattr(
        login_packets,
        "_patch_update_object_1773613176_0002_remote_flags",
        lambda payload: None,
    )

    ctx = SimpleNamespace(
        map_id=1,
        char_guid=14,
        exact_0002_mode="barncastle",
        exact_0002_remote_player=True,
    )

    assert login_packets.build_SMSG_UPDATE_OBJECT_1773613176_0002(ctx) == b"replay-built-payload"


def diff_bytes(a: bytes, b: bytes) -> list[tuple[int, int | None, int | None]]:
    """Return byte-level differences between two payloads."""
    differences: list[tuple[int, int | None, int | None]] = []
    max_len = max(len(a), len(b))

    for index in range(max_len):
        left = a[index] if index < len(a) else None
        right = b[index] if index < len(b) else None
        if left != right:
            differences.append((index, left, right))

    return differences


def diff_bytes_exact(a: bytes, b: bytes) -> list[tuple[int, int | None, int | None]]:
    """Return exact byte differences between two payloads."""
    return diff_bytes(a, b)


def _decode_packed_guid(mask: int, data: bytes) -> int:
    """Decode a WoW packed GUID from mask plus payload bytes."""
    raw = [0] * 8
    offset = 0
    for bit_index in range(8):
        if not (mask & (1 << bit_index)):
            continue
        raw[bit_index] = data[offset]
        offset += 1
    return int.from_bytes(bytes(raw), "little", signed=False)


def parse_create_header(payload: bytes) -> dict[str, int]:
    """Parse the stable CREATE_OBJECT header fields from the first update entry."""
    if len(payload) < 10:
        raise ValueError("payload is too short to contain a player CREATE_OBJECT")

    map_id = struct.unpack_from("<H", payload, 0)[0]
    update_count = struct.unpack_from("<I", payload, 2)[0]
    update_type = payload[6]
    guid_mask = payload[7]
    guid_size = int(guid_mask).bit_count()
    guid_data_start = 8
    guid_data_end = guid_data_start + guid_size
    guid = _decode_packed_guid(guid_mask, payload[guid_data_start:guid_data_end])
    object_type = payload[guid_data_end]
    body_offset = guid_data_end + 1

    return {
        "map_id": int(map_id),
        "update_count": int(update_count),
        "update_type": int(update_type),
        "guid_mask": int(guid_mask),
        "guid_size": int(guid_size),
        "guid": int(guid),
        "object_type": int(object_type),
        "body_offset": int(body_offset),
    }


def locate_update_field_region(payload: bytes) -> dict[str, int]:
    """Locate the field mask and field bytes inside the CREATE_OBJECT body."""
    header = parse_create_header(payload)
    body_offset = header["body_offset"]
    candidates: list[dict[str, int]] = []

    for mask_offset in range(body_offset, len(payload)):
        mask_blocks = payload[mask_offset]
        if mask_blocks <= 0:
            continue

        mask_size = int(mask_blocks) * 4
        remaining = len(payload) - (mask_offset + 1)
        if remaining < mask_size + 1:
            continue

        field_bytes_size = remaining - mask_size - 1
        if field_bytes_size < 0 or field_bytes_size % 4 != 0:
            continue

        mask_start = mask_offset + 1
        mask_end = mask_start + mask_size
        field_start = mask_end
        field_end = field_start + field_bytes_size
        mask_bytes = payload[mask_start:mask_end]
        enabled_bits = sum(byte.bit_count() for byte in mask_bytes)
        field_count = field_bytes_size // 4

        if enabled_bits != field_count:
            continue

        candidates.append(
            {
                "mask_offset": mask_offset,
                "mask_blocks": int(mask_blocks),
                "mask_start": mask_start,
                "mask_end": mask_end,
                "field_start": field_start,
                "field_end": field_end,
                "field_count": field_count,
                "trailing_zero_offset": field_end,
            }
        )

    if not candidates:
        raise ValueError("could not locate CREATE_OBJECT field region")

    candidates.sort(key=lambda item: (-item["field_count"], item["mask_offset"]))
    return candidates[0]


def locate_movement_region(payload: bytes) -> dict[str, int]:
    """Return the byte range between the create body start and field mask."""
    header = parse_create_header(payload)
    field_region = locate_update_field_region(payload)
    return {
        "start": header["body_offset"],
        "end": field_region["mask_offset"],
        "size": field_region["mask_offset"] - header["body_offset"],
    }


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


def patch_create_fields(
    ref_field_bytes: bytes,
    field_indices: list[int],
    srv_values: dict[int, int],
) -> bytes:
    """Patch reference field bytes with server-built values for matching indices."""
    output = bytearray(ref_field_bytes)
    offset = 0

    for field_index in field_indices:
        if field_index in srv_values:
            struct.pack_into("<I", output, offset, srv_values[field_index])
        offset += 4

    return bytes(output)


def diff_create_object_regions(a: bytes, b: bytes) -> dict[str, list[tuple[int, int | None, int | None]]]:
    """Return byte-level diffs split into CREATE_OBJECT regions."""
    a_region = locate_update_field_region(a)
    b_region = locate_update_field_region(b)

    a_mask_start = a_region["mask_offset"]
    a_mask_end = a_region["mask_end"]
    a_fields_start = a_region["field_start"]
    a_fields_end = a_region["field_end"]
    a_tail_start = a_region["trailing_zero_offset"]

    regions = {
        "header": (0, 10),
        "movement": (10, 76),
        "mask": (a_mask_start, a_mask_end),
        "fields": (a_fields_start, a_fields_end),
        "tail": (a_tail_start, len(a)),
    }

    result: dict[str, list[tuple[int, int | None, int | None]]] = {}
    for name, (start, end) in regions.items():
        region_diffs: list[tuple[int, int | None, int | None]] = []
        for index in range(start, end):
            left = a[index] if index < len(a) else None
            right = b[index] if index < len(b) else None
            if left != right:
                region_diffs.append((index, left, right))
        result[name] = region_diffs

    result["candidate_mask_meta"] = [
        (b_region["mask_offset"], b_region["mask_blocks"], b_region["field_count"])
    ]
    return result


def dump_movement_floats(payload: bytes) -> list[tuple[int, float]]:
    """Dump the movement region as 32-bit floats for debugging."""
    floats: list[tuple[int, float]] = []
    for offset in range(10, 76, 4):
        try:
            value = struct.unpack_from("<f", payload, offset)[0]
        except struct.error:
            continue
        floats.append((offset, float(value)))
    return floats


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


def diff_fields(a: dict[int, int], b: dict[int, int]) -> dict[int, tuple[int | None, int | None]]:
    """Return field-level differences keyed by field index."""
    differences: dict[int, tuple[int | None, int | None]] = {}
    for field_index in sorted(set(a) | set(b)):
        left = a.get(field_index)
        right = b.get(field_index)
        if left != right:
            differences[field_index] = (left, right)
    return differences


def export_missing_fields(reference_fields: dict[int, int], candidate_fields: dict[int, int]) -> None:
    """Print copy-paste friendly assignments for future create-builder work."""
    for field_index, (reference_value, _candidate_value) in diff_fields(
        reference_fields,
        candidate_fields,
    ).items():
        if reference_value is None:
            continue
        print(f"fields[{field_index}] = {reference_value}")


def test_reference_player_create_layout_is_stable() -> None:
    """Lock the verified SkyFire player CREATE_OBJECT layout."""
    payload = load_reference_payload()
    header = parse_create_header(payload)
    movement_region = locate_movement_region(payload)
    field_region = locate_update_field_region(payload)

    assert header == {
        "map_id": 1,
        "update_count": 1,
        "update_type": 2,
        "guid_mask": 0x01,
        "guid_size": 1,
        "guid": 0x000000000000000E,
        "object_type": 4,
        "body_offset": 10,
    }
    assert movement_region == {"start": 10, "end": 76, "size": 66}
    assert field_region["mask_offset"] == 76
    assert field_region["mask_blocks"] == 63
    assert field_region["field_start"] == 77 + 252
    assert field_region["field_end"] == 77 + 252 + 448
    assert field_region["field_count"] == 112
    assert payload[field_region["trailing_zero_offset"]] == 0


def test_reference_player_create_fields_are_self_consistent() -> None:
    """Ensure field parsing is stable before any future server-side create work."""
    payload = load_reference_payload()
    fields = parse_update_fields(payload)
    byte_diffs = diff_bytes(payload, payload)
    field_diffs = diff_fields(fields, fields)

    print(f"reference_create_capture={REFERENCE_CREATE_CAPTURE_NAME}")
    print(f"reference_len={len(payload)} field_count={len(fields)}")
    print(f"byte_diff_count={len(byte_diffs)} first_10={byte_diffs[:10]}")
    print(f"field_diff_count={len(field_diffs)} first_10={list(field_diffs.items())[:10]}")
    export_missing_fields(fields, fields)

    assert fields[0] == 14
    assert fields[4] == 25
    assert fields[7] == struct.unpack("<I", struct.pack("<f", 1.0))[0]
    assert fields[33] == 102
    assert fields[39] == 102
    assert fields[55] == 1
    assert fields[69] == 56
    assert fields[70] == 56
    assert fields[71] == 0
    assert fields[166] == 393479
    assert fields[167] == 16777220
    assert fields[168] == 1
    assert fields[1943] == 90
    assert field_diffs == {}
    assert byte_diffs == []


def test_create_object_debug_diff() -> None:
    """Print a structured region diff between reference and current create payload."""
    reference_payload = load_reference_payload()
    server_payload = build_server_payload()
    region_diffs = diff_create_object_regions(reference_payload, server_payload)

    for name, differences in region_diffs.items():
        print(f"[DIFF] {name}: {len(differences)} differences")
        if differences:
            print(differences[:10])


def test_movement_debug() -> None:
    """Print movement floats for the reference player CREATE_OBJECT capture."""
    reference_payload = load_reference_payload()
    floats = dump_movement_floats(reference_payload)

    for offset, value in floats:
        print(offset, value)


def test_create_object_byte_match() -> None:
    """Assert exact byte match once a server-built CREATE_OBJECT path exists."""
    if not CURRENT_CREATE_BUILDER_IS_SERVER_BUILT:
        pytest.skip("server-built player CREATE_OBJECT path is not implemented yet")

    reference_payload = load_reference_payload()
    server_payload = build_server_payload()
    differences = diff_bytes_exact(reference_payload, server_payload)

    assert not differences, f"Byte mismatch: {differences[:20]}"


def test_field_diff_baseline() -> None:
    """Measure the current field-region diff without header, movement, or mask."""
    reference_payload = load_reference_payload()
    server_payload = build_server_payload()

    region = locate_update_field_region(reference_payload)
    reference_fields = reference_payload[region["field_start"] : region["field_end"]]
    server_fields = server_payload[region["field_start"] : region["field_end"]]

    differences = diff_bytes(reference_fields, server_fields)

    print("field diff:", len(differences))

    assert len(differences) > 0


def test_extract_field_indices() -> None:
    """Expand the CREATE_OBJECT field mask into explicit field indices."""
    reference_payload = load_reference_payload()
    region = locate_update_field_region(reference_payload)
    mask_bytes = reference_payload[region["mask_start"] : region["mask_end"]]
    indices = extract_field_indices(mask_bytes, region["mask_blocks"])

    print(len(indices))

    assert len(indices) == region["field_count"]


def test_field_value_diff() -> None:
    """Convert the field byte diff into explicit field-index differences."""
    reference_payload = load_reference_payload()
    server_payload = build_server_payload()

    field_start, field_end = locate_field_region(reference_payload)
    region = locate_update_field_region(reference_payload)
    mask_bytes = reference_payload[region["mask_start"] : region["mask_end"]]
    indices = extract_field_indices(mask_bytes, region["mask_blocks"])

    reference_values = parse_field_values(reference_payload[field_start:field_end], indices)
    server_values = parse_field_values(server_payload[field_start:field_end], indices)
    differences = diff_field_values(reference_values, server_values)

    print("field value diffs:", len(differences))
    print("first 20:", differences[:20])

    assert len(differences) > 0


def test_patch_create_fields_with_server_values() -> None:
    """Patch the reference CREATE_OBJECT field block with server-built field values."""
    reference_payload = load_reference_payload()
    region = locate_update_field_region(reference_payload)
    mask_bytes = reference_payload[region["mask_start"] : region["mask_end"]]
    field_indices = extract_field_indices(mask_bytes, region["mask_blocks"])
    reference_field_bytes = reference_payload[region["field_start"] : region["field_end"]]
    reference_values = parse_field_values(reference_field_bytes, field_indices)

    ctx = SimpleNamespace(
        map_id=1,
        char_guid=14,
        world_guid=14,
        player_guid=14,
        race=4,
        gender=1,
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
    server_values = build_player_field_values(ctx)
    patched_field_bytes = patch_create_fields(reference_field_bytes, field_indices, server_values)
    patched_payload = bytearray(reference_payload)
    patched_payload[region["field_start"] : region["field_end"]] = patched_field_bytes

    baseline_server_payload = build_server_payload()
    baseline_differences = diff_bytes(reference_payload, baseline_server_payload)
    patched_differences = diff_bytes(reference_payload, bytes(patched_payload))
    patched_values = parse_field_values(patched_field_bytes, field_indices)
    field_differences = diff_field_values(reference_values, patched_values)

    print("create diff before:", len(baseline_differences))
    print("create diff:", len(patched_differences))
    print("field value diffs after patch:", len(field_differences))

    assert len(field_differences) < 102
    assert len(patched_differences) < len(baseline_differences)


def test_player_create_flag_off() -> None:
    """Keep replay CREATE_OBJECT behavior unchanged while the flag is disabled."""
    replay_payload = build_create_payload(use_server_built_player_create=False)
    payload = build_create_payload(use_server_built_player_create=False)

    assert payload == replay_payload


def test_player_create_flag_on() -> None:
    """Ensure the template-based CREATE_OBJECT path produces a payload when enabled."""
    payload = build_create_payload(use_server_built_player_create=True)

    assert payload is not None


def test_player_create_field_match_reference() -> None:
    """The template-based CREATE_OBJECT path should preserve header and movement."""
    payload = build_create_payload(use_server_built_player_create=True)
    reference_payload = load_reference_payload()

    region_diffs = diff_create_object_regions(reference_payload, payload)

    assert region_diffs["header"] == []
    assert region_diffs["movement"] == []
    assert region_diffs["mask"] == []
    assert region_diffs["tail"] == []


def test_player_create_direct_field_match_reference() -> None:
    """The direct-header CREATE_OBJECT path should preserve header and movement."""
    payload = build_create_payload(
        use_server_built_player_create=True,
        use_server_built_player_create_direct=True,
    )
    reference_payload = load_reference_payload()

    region_diffs = diff_create_object_regions(reference_payload, payload)

    assert region_diffs["header"] == []
    assert region_diffs["movement"] == []
    assert region_diffs["mask"] == []
    assert region_diffs["tail"] == []


def test_build_player_field_values_sets_alliance_primary_language_skill() -> None:
    """Alliance should mirror the old working barncastle language/riding block."""
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
    """Horde should mirror the old working barncastle language/riding block."""
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
        use_server_built_player_create=True,
        use_server_built_player_create_direct=True,
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
        use_server_built_player_create=True,
        use_server_built_player_create_direct=True,
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


def test_player_create_patches_language_mask_for_team() -> None:
    """The new create path should mirror the old replay language-mask patch."""
    alliance_payload = build_create_payload(
        use_server_built_player_create=True,
        use_server_built_player_create_direct=True,
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
        use_server_built_player_create=True,
        use_server_built_player_create_direct=True,
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

    common_mask = (1 << 7).to_bytes(4, "little")
    orcish_mask = (1 << 1).to_bytes(4, "little")

    assert common_mask in alliance_payload
    assert orcish_mask not in alliance_payload
    assert orcish_mask in horde_payload


def test_horde_player_create_keeps_level_field_in_final_payload() -> None:
    """Horde create should include field 55 and keep the runtime level value."""
    payload = build_create_payload(
        use_server_built_player_create=True,
        use_server_built_player_create_direct=True,
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
        use_server_built_player_create=True,
        use_server_built_player_create_direct=True,
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
        use_server_built_player_create=False,
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


def test_horde_replay_and_server_create_match_remaining_sensitive_fields() -> None:
    """Lock replay vs server parity for the currently known Horde-sensitive fields."""
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
    replay_payload = build_create_payload(use_server_built_player_create=False, ctx=ctx)
    server_payload = build_create_payload(
        use_server_built_player_create=True,
        use_server_built_player_create_direct=True,
        ctx=ctx,
    )

    replay_region = locate_update_field_region(replay_payload)
    replay_indices = extract_field_indices(
        replay_payload[replay_region["mask_start"] : replay_region["mask_end"]],
        replay_region["mask_blocks"],
    )
    replay_values = parse_field_values(
        replay_payload[replay_region["field_start"] : replay_region["field_end"]],
        replay_indices,
    )

    server_region = locate_update_field_region(server_payload)
    server_indices = extract_field_indices(
        server_payload[server_region["mask_start"] : server_region["mask_end"]],
        server_region["mask_blocks"],
    )
    server_values = parse_field_values(
        server_payload[server_region["field_start"] : server_region["field_end"]],
        server_indices,
    )

    target_fields = [30, 57, 166, 167, 168, 1154, 1282, 1410, 1943]
    differences = {
        field_index: (replay_values.get(field_index), server_values.get(field_index))
        for field_index in target_fields
        if replay_values.get(field_index) != server_values.get(field_index)
    }

    assert differences == {}


def test_horde_replay_and_server_create_match_bias_sensitive_fields() -> None:
    """Replay and server-built Horde create should match for the remaining bias-sensitive fields."""
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
    replay_payload = build_create_payload(use_server_built_player_create=False, ctx=ctx)
    server_payload = build_create_payload(
        use_server_built_player_create=True,
        use_server_built_player_create_direct=True,
        ctx=ctx,
    )

    replay_region = locate_update_field_region(replay_payload)
    replay_indices = extract_field_indices(
        replay_payload[replay_region["mask_start"] : replay_region["mask_end"]],
        replay_region["mask_blocks"],
    )
    replay_values = parse_field_values(
        replay_payload[replay_region["field_start"] : replay_region["field_end"]],
        replay_indices,
    )

    server_region = locate_update_field_region(server_payload)
    server_indices = extract_field_indices(
        server_payload[server_region["mask_start"] : server_region["mask_end"]],
        server_region["mask_blocks"],
    )
    server_values = parse_field_values(
        server_payload[server_region["field_start"] : server_region["field_end"]],
        server_indices,
    )

    target_fields = [57, 166, 167, 168, 1943]
    differences = {}
    for field_index in target_fields:
        replay_value = replay_values.get(field_index)
        server_value = server_values.get(field_index)
        if replay_value != server_value:
            Logger.info(f"[BIAS DIFF] {field_index}: replay={replay_value} server={server_value}")
            differences[field_index] = (replay_value, server_value)

    assert differences == {}


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
        use_server_built_player_create=True,
        use_server_built_player_create_direct=True,
        ctx=ctx,
    )
    parsed_fields = parse_update_fields(payload)

    assert sum(byte.bit_count() for byte in mask_bytes) == len(field_values)
    assert set(field_indices) == set(field_values)
    assert len(parsed_fields) == len(field_values)
    assert set(parsed_fields) == set(field_values)


def test_server_built_movement_block_matches_reference_bytes() -> None:
    """Build the movement block from code-only constants and require byte identity."""
    reference_payload = load_reference_payload()
    reference_block = reference_payload[10:76]
    ctx = SimpleNamespace(
        x=16212.216796875,
        y=16253.169921875,
        z=14.770503044128418,
        orientation=1.6979784965515137,
    )

    built_block = build_movement_block(ctx)

    assert built_block == reference_block


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
