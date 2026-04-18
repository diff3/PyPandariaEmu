from __future__ import annotations

import importlib
import math
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import types


CREATE_BEFORE_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "skyfire548"
    / "captures"
    / "focus"
    / "debug"
    / "SMSG_UPDATE_OBJECT_1776451639_0458.json"
)
CREATE_AFTER_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "skyfire548"
    / "captures"
    / "focus"
    / "debug"
    / "SMSG_UPDATE_OBJECT_1776498325_0153.json"
)
MOVE_BEFORE_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "skyfire548"
    / "captures"
    / "focus"
    / "debug"
    / "MSG_MOVE_START_FORWARD_1776451643_0465.json"
)
MOVE_AFTER_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "skyfire548"
    / "captures"
    / "focus"
    / "debug"
    / "MSG_MOVE_START_FORWARD_1776498340_0166.json"
)
MOVE_JUMP_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "skyfire548"
    / "captures"
    / "focus"
    / "debug"
    / "MSG_MOVE_JUMP_1776498345_0168.json"
)
MOVE_FALL_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "skyfire548"
    / "captures"
    / "focus"
    / "debug"
    / "MSG_MOVE_FALL_LAND_1776498346_0170.json"
)


def _import_replay_with_stubs():
    """Import replay with minimal stubs so load_sniff_payload stays reusable."""
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


def load_sniff_payload(path: str | Path) -> bytes:
    """Load a capture payload through the existing replay helper."""
    replay = _import_replay_with_stubs()
    return replay.load_sniff_payload(path)


def extract_movement_block(payload: bytes) -> bytes:
    """Return the player CREATE_OBJECT movement block."""
    return bytes(payload[10:76])


def extract_position_triples(payload: bytes) -> list[tuple[int, float, float, float]]:
    """Extract candidate x/y/z triples from a MOVE packet."""
    triples: list[tuple[int, float, float, float]] = []

    for index in range(0, len(payload) - 12 + 1):
        try:
            x_value, y_value, z_value = struct.unpack_from("<fff", payload, index)
        except struct.error:
            continue

        if not all(math.isfinite(value) for value in (x_value, y_value, z_value)):
            continue

        if -50000 < x_value < 50000 and -50000 < y_value < 50000:
            triples.append((index, float(x_value), float(y_value), float(z_value)))

    return triples


def find_best_delta_pair(
    triples_before: list[tuple[int, float, float, float]],
    triples_after: list[tuple[int, float, float, float]],
) -> tuple[float, float, float] | None:
    """Find the strongest matching x/y movement delta between two MOVE packets."""
    best: tuple[float, float, float] | None = None

    for (_offset_before, x_before, y_before, _z_before), (
        _offset_after,
        x_after,
        y_after,
        _z_after,
    ) in zip(triples_before, triples_after):
        if not (
            abs(x_before) > 1000
            and abs(y_before) > 1000
            and abs(x_after) > 1000
            and abs(y_after) > 1000
        ):
            continue

        delta_x = x_after - x_before
        delta_y = y_after - y_before

        if abs(delta_x) < 0.001 and abs(delta_y) < 0.001:
            continue

        # Reject misaligned triples that imply impossible single-step deltas.
        if abs(delta_x) > 100 or abs(delta_y) > 100:
            continue

        score = abs(delta_x) + abs(delta_y)
        if best is None or score > best[0]:
            best = (score, float(delta_x), float(delta_y))

    return best


def extract_all_floats(block: bytes) -> list[tuple[int, float]]:
    """Extract all finite float candidates from a byte block."""
    results: list[tuple[int, float]] = []
    for index in range(0, len(block) - 4 + 1):
        try:
            value = struct.unpack_from("<f", block, index)[0]
        except struct.error:
            continue

        if math.isfinite(value):
            results.append((index, float(value)))

    return results


def find_matching_deltas(
    block_before: bytes,
    block_after: bytes,
    delta_x: float,
    delta_y: float,
) -> list[tuple[str, int, float]]:
    """Find float offsets in the CREATE_OBJECT block that match x/y deltas."""
    matches: list[tuple[str, int, float]] = []

    floats_before = extract_all_floats(block_before)
    floats_after = extract_all_floats(block_after)

    for (offset_before, value_before), (offset_after, value_after) in zip(floats_before, floats_after):
        if offset_before != offset_after:
            continue

        delta = value_after - value_before

        if abs(delta - delta_x) < 0.01:
            matches.append(("X", offset_before, float(delta)))

        if abs(delta - delta_y) < 0.01:
            matches.append(("Y", offset_before, float(delta)))

    return matches


def extract_vertical_candidates(payload: bytes) -> list[tuple[int, float]]:
    """Extract plausible vertical-position floats from a MOVE packet."""
    candidates: list[tuple[int, float]] = []
    for index in range(0, len(payload) - 4 + 1):
        try:
            value = struct.unpack_from("<f", payload, index)[0]
        except struct.error:
            continue

        if not math.isfinite(value):
            continue

        if 0.1 < abs(value) < 100:
            candidates.append((index, float(value)))

    return candidates


def find_best_z_offset(
    create_before: bytes,
    create_after: bytes,
    move_before: bytes,
    move_after: bytes,
) -> tuple[int, float, float, tuple[int, float], tuple[int, float]]:
    """Find the CREATE_OBJECT float offset that best matches vertical delta."""
    create_block_before = extract_movement_block(create_before)
    create_block_after = extract_movement_block(create_after)
    before_candidates = extract_vertical_candidates(move_before)
    after_candidates = extract_vertical_candidates(move_after)

    best: tuple[int, float, float, tuple[int, float], tuple[int, float]] | None = None
    best_error: float | None = None

    for before_candidate in before_candidates:
        for after_candidate in after_candidates:
            delta_move = after_candidate[1] - before_candidate[1]

            for offset in range(0, len(create_block_before) - 4 + 1):
                value_before = struct.unpack_from("<f", create_block_before, offset)[0]
                value_after = struct.unpack_from("<f", create_block_after, offset)[0]
                if not (math.isfinite(value_before) and math.isfinite(value_after)):
                    continue

                delta_create = value_after - value_before
                error = abs(delta_create - delta_move)

                if best_error is None or error < best_error:
                    best_error = error
                    best = (
                        offset,
                        float(delta_move),
                        float(delta_create),
                        before_candidate,
                        after_candidate,
                    )

    if best is None:
        raise AssertionError("no z offset candidate found")

    return best


def test_find_xy_offsets_from_delta() -> None:
    """Match MOVE packet x/y deltas against float deltas in CREATE_OBJECT."""
    create_before = load_sniff_payload(CREATE_BEFORE_PATH)
    create_after = load_sniff_payload(CREATE_AFTER_PATH)
    move_before = load_sniff_payload(MOVE_BEFORE_PATH)
    move_after = load_sniff_payload(MOVE_AFTER_PATH)

    triples_before = extract_position_triples(move_before)
    triples_after = extract_position_triples(move_after)

    best = find_best_delta_pair(triples_before, triples_after)
    assert best is not None

    _score, delta_x, delta_y = best

    print("\n=== MOVE DELTA ===")
    print(f"dx={delta_x} dy={delta_y}")

    block_before = extract_movement_block(create_before)
    block_after = extract_movement_block(create_after)

    matches = find_matching_deltas(block_before, block_after, delta_x, delta_y)

    print("\n=== MATCHES ===")
    for match in matches:
        print(match)

    assert matches


def test_find_z_offset_from_delta() -> None:
    """Match a vertical MOVE delta against float deltas in CREATE_OBJECT."""
    create_before = load_sniff_payload(CREATE_BEFORE_PATH)
    create_after = load_sniff_payload(CREATE_AFTER_PATH)
    move_before = load_sniff_payload(MOVE_BEFORE_PATH)

    results = [
        find_best_z_offset(
            create_before,
            create_after,
            move_before,
            load_sniff_payload(MOVE_JUMP_PATH),
        ),
        find_best_z_offset(
            create_before,
            create_after,
            move_before,
            load_sniff_payload(MOVE_FALL_PATH),
        ),
    ]
    best = min(results, key=lambda item: abs(item[2] - item[1]))

    offset, delta_move, delta_create, before_candidate, after_candidate = best

    print("\n=== Z DELTA ===")
    print(f"move_before={before_candidate}")
    print(f"move_after={after_candidate}")
    print(f"dz_move={delta_move}")
    print(f"dz_create={delta_create}")
    print(f"offset={offset}")

    assert offset == 62
    assert abs(delta_create - delta_move) < 0.2
