from __future__ import annotations

import importlib
import math
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import types


CREATE_OBJECT_CAPTURE_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "proxy"
    / "skyfire548"
    / "captures"
    / "focus"
    / "debug"
    / "SMSG_UPDATE_OBJECT_1776498325_0153.json"
)
FACING_CAPTURE_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "proxy"
    / "skyfire548"
    / "captures"
    / "focus"
    / "debug"
    / "MSG_MOVE_SET_FACING_1776498333_0160.json"
)
MOVE_CAPTURE_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "proxy"
    / "skyfire548"
    / "captures"
    / "focus"
    / "debug"
    / "MSG_MOVE_START_FORWARD_1776498340_0166.json"
)
FACING_CAPTURE_NAMES = [
    "MSG_MOVE_SET_FACING_1776498333_0160.json",
    "MSG_MOVE_SET_FACING_1776498334_0161.json",
    "MSG_MOVE_SET_FACING_1776498334_0162.json",
    "MSG_MOVE_SET_FACING_1776498334_0163.json",
    "MSG_MOVE_SET_FACING_1776498334_0164.json",
]


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


def load_sniff_payload(path: str | Path) -> bytes:
    """Load a capture payload through the existing replay helper."""
    replay = _import_replay_with_stubs()
    return replay.load_sniff_payload(path)


def extract_movement_block(payload: bytes) -> bytes:
    """Return the player CREATE_OBJECT movement block bytes."""
    return bytes(payload[10:76])


def read_floats(payload: bytes) -> list[tuple[int, float]]:
    """Extract all finite float candidates from a payload."""
    results: list[tuple[int, float]] = []
    for index in range(0, len(payload) - 4 + 1):
        try:
            value = struct.unpack_from("<f", payload, index)[0]
        except struct.error:
            continue
        if math.isfinite(value):
            results.append((index, float(value)))
    return results


def extract_orientation_from_move(payload: bytes) -> float | None:
    """Extract a likely orientation from a MOVE_SET_FACING packet."""
    for _index, value in read_floats(payload):
        if -6.5 < value < 6.5 and abs(value) > 0.01:
            return value
    return None


def extract_orientation_from_move_packet(payload: bytes) -> float:
    """Extract a stable orientation candidate from a MOVE_SET_FACING packet."""
    candidates: list[float] = []
    for _index, value in read_floats(payload):
        if -math.pi * 2 < value < math.pi * 2 and abs(value) > 0.01:
            candidates.append(float(value))

    if not candidates:
        raise AssertionError("no orientation candidate found in MOVE_SET_FACING payload")

    candidates.sort()
    return candidates[len(candidates) // 2]


def float_at(payload: bytes, offset: int) -> float:
    """Read a 32-bit float at a byte offset."""
    return float(struct.unpack_from("<f", payload, offset)[0])


def find_orientation_offset(create_payload: bytes, move_payloads: list[bytes]) -> tuple[int | None, float]:
    """Score all movement-block float offsets against orientation samples."""
    movement_block = extract_movement_block(create_payload)
    samples = [extract_orientation_from_move_packet(payload) for payload in move_payloads]
    sample_average = sum(samples) / len(samples)
    sample_min = min(samples)
    sample_max = max(samples)
    sample_variation = sample_max - sample_min

    best_offset: int | None = None
    best_score = float("inf")

    for offset in range(0, len(movement_block) - 4 + 1):
        try:
            score = 0.0
            value = float_at(movement_block, offset)
        except struct.error:
            continue

        if not math.isfinite(value):
            continue

        if abs(value - sample_average) < 0.2 and sample_variation > 0.3:
            continue

        penalty = 0.0
        if value < sample_min or value > sample_max:
            penalty += min(abs(value - sample_min), abs(value - sample_max))

        for sample in samples:
            score += abs(value - sample)

        score += penalty

        if score < best_score:
            best_score = score
            best_offset = offset

    return best_offset, float(best_score)


def extract_position_candidates(payload: bytes) -> list[tuple[int, float, float, float]]:
    """Extract plausible world-coordinate triples from a MOVE packet."""
    candidates: list[tuple[int, float, float, float]] = []
    for index in range(0, len(payload) - 12 + 1):
        try:
            x_value, y_value, z_value = struct.unpack_from("<fff", payload, index)
        except struct.error:
            continue

        if not all(math.isfinite(value) for value in (x_value, y_value, z_value)):
            continue

        if -20000 < x_value < 20000 and -20000 < y_value < 20000 and -2000 < z_value < 2000:
            candidates.append((index, float(x_value), float(y_value), float(z_value)))

    return candidates


def map_values_to_create_block(create_payload: bytes, values: dict[str, float]) -> dict[str, object]:
    """Locate known movement values inside the CREATE_OBJECT movement block."""
    block = extract_movement_block(create_payload)
    matches: dict[str, object] = {}

    for name, target in values.items():
        best: tuple[float, int, float] | None = None

        for offset in range(0, len(block) - 4):
            try:
                value = struct.unpack_from("<f", block, offset)[0]
            except struct.error:
                continue

            if not math.isfinite(value):
                continue

            diff = abs(value - target)
            if diff < 0.001:
                matches[name] = offset
                break

            if best is None or diff < best[0]:
                best = (diff, offset, float(value))

        if name not in matches and best is not None:
            matches[name] = ("approx", best)

    return matches


def test_map_movement_fields() -> None:
    """Map MOVE packet ground-truth values into the player CREATE_OBJECT block."""
    create_payload = load_sniff_payload(CREATE_OBJECT_CAPTURE_PATH)
    facing_payload = load_sniff_payload(FACING_CAPTURE_PATH)
    move_payload = load_sniff_payload(MOVE_CAPTURE_PATH)

    orientation = extract_orientation_from_move(facing_payload)
    assert orientation is not None

    position_candidates = extract_position_candidates(move_payload)
    assert position_candidates

    candidate_offset, x_value, y_value, z_value = position_candidates[0]

    print("\n=== MOVE VALUES ===")
    print(f"orientation={orientation}")
    print(f"candidate_offset={candidate_offset}")
    print(f"x={x_value} y={y_value} z={z_value}")

    mapping = map_values_to_create_block(
        create_payload,
        {
            "orientation": orientation,
            "x": x_value,
            "y": y_value,
            "z": z_value,
        },
    )

    print("\n=== MAPPING ===")
    for key, value in mapping.items():
        print(key, "->", value)

    assert True


def test_find_orientation_offset() -> None:
    """Find the best orientation offset inside the player CREATE_OBJECT block."""
    base = CREATE_OBJECT_CAPTURE_PATH.parent
    create_payload = load_sniff_payload(base / "SMSG_UPDATE_OBJECT_1776498325_0153.json")
    move_payloads = [load_sniff_payload(base / name) for name in FACING_CAPTURE_NAMES]

    samples = [extract_orientation_from_move_packet(payload) for payload in move_payloads]
    print("\n=== ORIENTATION SAMPLES ===")
    for sample in samples:
        print(sample)

    offset, score = find_orientation_offset(create_payload, move_payloads)

    print(f"BEST OFFSET: {offset} score={score}")

    assert offset is not None
    assert offset == 33
    assert score < 3.0
