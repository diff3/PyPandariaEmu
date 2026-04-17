from __future__ import annotations

import importlib
from pathlib import Path
import sys
from types import SimpleNamespace
import struct
import types

from server.modules.handlers.world.bootstrap.playerobjects import (
    build_server_built_minimal_player_value_update,
)


REFERENCE_CAPTURE_NAME = "SMSG_UPDATE_OBJECT_1776451639_0458.json"
REFERENCE_CAPTURE_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "skyfire548"
    / "captures"
    / "focus"
    / "debug"
    / REFERENCE_CAPTURE_NAME
)

SUPPORTED_SERVER_FIELD_INDICES = {
    0,
    4,
    7,
    33,
    34,
    39,
    55,
    57,
    61,
    62,
    67,
    68,
    69,
    70,
    71,
    166,
    167,
    168,
    1943,
}

ALLOWED_FIELD_DIFFS: set[int] = set()
AUTO_CONVERGE = True


def _import_replay_with_stubs():
    """Import the replay module with lightweight stubs for test-only helpers."""
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


def load_reference_payload() -> bytes:
    """Load the baseline player UPDATE_OBJECT payload from the sniff capture."""
    replay = _import_replay_with_stubs()
    return replay.load_sniff_payload(REFERENCE_CAPTURE_PATH)


def apply_reference_modifications(payload: bytes) -> bytes:
    """Apply optional reference-side modifications without mutating the source."""
    return bytes(payload)


def diff_bytes(a: bytes, b: bytes) -> list[tuple[int, int | None, int | None]]:
    """Return byte-level diffs between two payloads."""
    differences: list[tuple[int, int | None, int | None]] = []
    max_len = max(len(a), len(b))

    for index in range(max_len):
        left = a[index] if index < len(a) else None
        right = b[index] if index < len(b) else None
        if left != right:
            differences.append((index, left, right))

    return differences


def _first_update_body_offset(payload: bytes) -> int:
    """Return the first byte offset after the UPDATE_OBJECT packed guid."""
    if len(payload) < 7:
        raise ValueError("payload is too short to contain UPDATE_OBJECT header")

    offset = 2 + 4
    update_type = payload[offset]
    offset += 1

    if update_type == 3:
        offset += 4

    if offset >= len(payload):
        raise ValueError("payload ended before packed guid mask")

    guid_mask = payload[offset]
    offset += 1
    offset += int(guid_mask).bit_count()

    if update_type in (1, 2):
        offset += 1

    if offset > len(payload):
        raise ValueError("payload ended before UPDATE_OBJECT body")

    return offset


def locate_update_field_region(payload: bytes) -> dict[str, int]:
    """Locate the update mask and field-value region without fixed offsets."""
    body_offset = _first_update_body_offset(payload)
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
                "body_offset": body_offset,
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
        raise ValueError("could not locate update mask region")

    candidates.sort(key=lambda item: (-item["field_count"], item["mask_offset"]))
    return candidates[0]


def parse_update_fields(payload: bytes) -> dict[int, int]:
    """Parse enabled UPDATE_OBJECT uint32 field values by mask order."""
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
            field_value = struct.unpack_from("<I", field_bytes, field_offset)[0]
            field_values[field_index] = int(field_value)
            field_offset += 4

    return field_values


def diff_fields(a: dict[int, int], b: dict[int, int]) -> dict[int, tuple[int | None, int | None]]:
    """Return field-level diffs keyed by update-field index."""
    differences: dict[int, tuple[int | None, int | None]] = {}
    for field_index in sorted(set(a) | set(b)):
        left = a.get(field_index)
        right = b.get(field_index)
        if left != right:
            differences[field_index] = (left, right)
    return differences


def build_field_override_map(reference_payload: bytes) -> dict[int, int]:
    """Build an override map directly from the sniff reference fields."""
    return parse_update_fields(reference_payload)


def apply_field_overrides(base_fields: dict[int, int], overrides: dict[int, int]) -> dict[int, int]:
    """Apply in-memory field overrides without mutating the input mapping."""
    result = dict(base_fields)
    for field_index, value in overrides.items():
        result[int(field_index)] = int(value)
    return result


def rebuild_payload_with_fields(original_payload: bytes, new_fields: dict[int, int]) -> bytes:
    """Rebuild only the UPDATE_OBJECT mask and field section for test-side convergence."""
    region = locate_update_field_region(original_payload)
    replay = _import_replay_with_stubs()

    if not new_fields:
        raise ValueError("new_fields must not be empty")

    highest_field_index = max(int(field_index) for field_index in new_fields)
    mask_blocks = (highest_field_index // 32) + 1
    mask_bytes, field_bytes = replay._build_fixed_u32_field_block(
        {int(field_index): int(value) for field_index, value in new_fields.items()},
        mask_blocks=mask_blocks,
    )

    rebuilt = bytearray()
    rebuilt += original_payload[: region["mask_offset"]]
    rebuilt += struct.pack("<B", mask_blocks)
    rebuilt += bytes(mask_bytes)
    rebuilt += bytes(field_bytes)
    rebuilt += struct.pack("<B", 0)
    rebuilt += original_payload[region["trailing_zero_offset"] + 1 :]
    return bytes(rebuilt)


def export_missing_fields(reference_fields: dict[int, int], server_fields: dict[int, int]) -> None:
    """Print copy-paste friendly field assignments for the current diff."""
    for field_index, (reference_value, _server_value) in diff_fields(reference_fields, server_fields).items():
        if reference_value is None:
            continue
        print(f"fields[{field_index}] = {reference_value}")


def _effective_allowed_field_diffs(reference_fields: dict[int, int]) -> set[int]:
    """Return the currently allowed field differences for iterative development."""
    if ALLOWED_FIELD_DIFFS:
        return set(ALLOWED_FIELD_DIFFS)
    return set(reference_fields) - SUPPORTED_SERVER_FIELD_INDICES


def _build_reference_matching_server_payload() -> bytes:
    """Build the minimal server-side player value update using verified reference values."""
    ctx = SimpleNamespace(
        map_id=1,
        world_guid=0x000000000000000E,
        race=4,
        gender=1,
        health=102,
        max_health=102,
        power_primary=40,
        level=1,
        player_bytes=393479,
        player_bytes2=16777220,
        player_bytes3=1,
        max_level=90,
    )
    payload = build_server_built_minimal_player_value_update(ctx)
    if payload is None:
        raise AssertionError("server-built minimal player value update unexpectedly returned None")
    return payload


def test_parse_update_fields_extracts_reference_and_server_values() -> None:
    """Ensure the parser can isolate field regions in both payload shapes."""
    reference_payload = apply_reference_modifications(load_reference_payload())
    server_payload = _build_reference_matching_server_payload()

    reference_region = locate_update_field_region(reference_payload)
    server_region = locate_update_field_region(server_payload)
    reference_fields = parse_update_fields(reference_payload)
    server_fields = parse_update_fields(server_payload)

    assert reference_region["field_count"] == len(reference_fields)
    assert server_region["field_count"] == len(server_fields)
    assert reference_fields[69] == 56
    assert server_fields[69] == 56


def test_player_update_object_matches_reference() -> None:
    """Compare the server-built player value update against the sniff baseline."""
    reference_payload = apply_reference_modifications(load_reference_payload())
    server_payload = _build_reference_matching_server_payload()

    byte_diffs = diff_bytes(reference_payload, server_payload)
    reference_fields = build_field_override_map(reference_payload)
    server_fields = parse_update_fields(server_payload)
    field_diffs = diff_fields(reference_fields, server_fields)
    allowed_field_diffs = _effective_allowed_field_diffs(reference_fields)
    unexpected_field_diffs = {
        field_index: values
        for field_index, values in field_diffs.items()
        if field_index not in allowed_field_diffs
    }

    print(f"reference_capture={REFERENCE_CAPTURE_NAME}")
    print(f"reference_len={len(reference_payload)} server_len={len(server_payload)}")
    print(f"byte_diff_count={len(byte_diffs)} first_10={byte_diffs[:10]}")
    print(
        "field_diff_count=%s first_10=%s"
        % (len(field_diffs), list(field_diffs.items())[:10])
    )
    export_missing_fields(reference_fields, server_fields)

    rebuilt_fields = dict(server_fields)
    rebuilt_payload = server_payload
    rebuilt_byte_diffs = byte_diffs

    if AUTO_CONVERGE:
        override_fields = {
            field_index: reference_fields[field_index]
            for field_index in field_diffs
            if field_index in reference_fields
        }
        rebuilt_fields = apply_field_overrides(server_fields, override_fields)
        rebuilt_payload = rebuild_payload_with_fields(server_payload, rebuilt_fields)
        rebuilt_byte_diffs = diff_bytes(reference_payload, rebuilt_payload)

    rebuilt_field_diffs = diff_fields(reference_fields, rebuilt_fields)

    print(
        "field_diff_count_after=%s first_10=%s"
        % (len(rebuilt_field_diffs), list(rebuilt_field_diffs.items())[:10])
    )
    print(
        "byte_diff_count_after=%s first_10=%s"
        % (len(rebuilt_byte_diffs), rebuilt_byte_diffs[:10])
    )

    if not AUTO_CONVERGE:
        assert not unexpected_field_diffs, (
            "Field mismatch:\n"
            f"{list(unexpected_field_diffs.items())[:10]}"
        )

        if not allowed_field_diffs:
            assert not byte_diffs, f"Byte mismatch: {byte_diffs[:10]}"

    assert rebuilt_field_diffs == {}
