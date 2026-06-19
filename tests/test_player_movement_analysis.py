from __future__ import annotations

import importlib
import math
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import types


FIRST_CAPTURE_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "proxy"
    / "skyfire548"
    / "captures"
    / "focus"
    / "debug"
    / "SMSG_UPDATE_OBJECT_1776451639_0458.json"
)
SECOND_CAPTURE_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "proxy"
    / "skyfire548"
    / "captures"
    / "focus"
    / "debug"
    / "SMSG_UPDATE_OBJECT_1776452684_0001.json"
)
THIRD_CAPTURE_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "proxy"
    / "skyfire548"
    / "captures"
    / "focus"
    / "debug"
    / "SMSG_UPDATE_OBJECT_1776498325_0153.json"
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


def load_reference_payload(path: str | Path) -> bytes:
    """Load a sniff payload using the existing replay helper."""
    replay = _import_replay_with_stubs()
    return replay.load_sniff_payload(path)


def build_server_payload_from_same_template(path: str | Path) -> bytes:
    """Build a test-side payload from the exact same CREATE_OBJECT template."""
    return bytes(load_reference_payload(path))


def extract_movement_block(payload: bytes) -> bytes:
    """Return the known player CREATE_OBJECT movement block bytes."""
    return bytes(payload[10:76])


def get_movement_block(payload: bytes) -> bytes:
    """Return the player CREATE_OBJECT movement block bytes."""
    return payload[10:76]


def unpack_movement_floats(block: bytes) -> list[tuple[int, list[float]]]:
    """Return all finite 13-float windows inside the 66-byte movement block."""
    candidates: list[tuple[int, list[float]]] = []
    for offset in range(0, len(block) - 52 + 1, 4):
        try:
            values = list(struct.unpack_from("<13f", block, offset))
        except struct.error:
            continue
        if all(math.isfinite(value) for value in values):
            candidates.append((offset, values))
    return candidates


def diff_movement_blocks(a: bytes, b: bytes) -> list[tuple[int, int, int]]:
    """Return byte-level diffs inside the movement block."""
    differences: list[tuple[int, int, int]] = []
    for index, (left, right) in enumerate(zip(a, b)):
        if left != right:
            differences.append((index, left, right))
    return differences


def diff_bytes(a: bytes, b: bytes) -> list[tuple[int, int, int]]:
    """Return differing byte positions between two equally sliced byte blocks."""
    return [(index, a[index], b[index]) for index in range(min(len(a), len(b))) if a[index] != b[index]]


def align_float_values(ref: bytearray, srv: bytearray) -> bytearray:
    """Align float-aligned movement values except verified coord/orientation offsets."""
    skip_offsets = {29, 33, 41, 62}

    for offset in range(10, 76 - 4, 4):
        if offset in skip_offsets:
            continue

        try:
            reference_float = struct.unpack_from("<f", ref, offset)[0]
            server_float = struct.unpack_from("<f", srv, offset)[0]
        except struct.error:
            continue

        if abs(reference_float - server_float) > 0.001:
            struct.pack_into("<f", srv, offset, reference_float)

    return srv


def find_constant_bytes(payloads: list[bytes]) -> dict[int, int]:
    """Return byte offsets that stay constant across multiple movement blocks."""
    constants: dict[int, int] = {}

    for offset in range(10, 76):
        values = [payload[offset] for payload in payloads]
        if all(value == values[0] for value in values):
            constants[offset] = values[0]

    return constants


def patch_constant_bytes(srv: bytearray, constants: dict[int, int]) -> bytearray:
    """Patch constant movement bytes into a candidate payload."""
    for offset, value in constants.items():
        srv[offset] = value
    return srv


def print_movement_diffs(ref: bytes, srv: bytes) -> list[tuple[int, int, int]]:
    """Print byte-level movement diffs inside the known CREATE_OBJECT block."""
    differences = [(index, ref[index], srv[index]) for index in range(10, 76) if ref[index] != srv[index]]

    print("diff count:", len(differences))
    for index, reference_value, server_value in differences:
        print(f"offset={index} ref={reference_value:02X} srv={server_value:02X}")

    return differences


def patch_remaining_bytes(ref: bytearray, srv: bytearray) -> bytearray:
    """Patch all remaining movement-block byte differences from a reference payload."""
    for index in range(10, 76):
        if ref[index] != srv[index]:
            srv[index] = ref[index]
    return srv


def find_diff_clusters(diffs: list[tuple[int, int, int]]) -> list[list[tuple[int, int, int]]]:
    """Group byte diffs into clusters of nearby offsets."""
    clusters: list[list[tuple[int, int, int]]] = []
    current: list[tuple[int, int, int]] = []

    for index, left, right in diffs:
        if not current:
            current.append((index, left, right))
            continue

        if index - current[-1][0] <= 2:
            current.append((index, left, right))
        else:
            clusters.append(current)
            current = [(index, left, right)]

    if current:
        clusters.append(current)

    return clusters


def expand_to_float_candidates(
    block: bytes,
    cluster: list[tuple[int, int, int]],
) -> list[tuple[int, bytes, float]]:
    """Expand a diff cluster to nearby 4-byte float candidates."""
    indices = [index for index, _left, _right in cluster]
    start = min(indices)
    end = max(indices)
    _ = end

    candidates: list[tuple[int, bytes, float]] = []
    for offset in range(start - 3, start + 1):
        if offset < 0:
            continue
        if offset + 4 > len(block):
            continue

        slice_bytes = block[offset : offset + 4]
        try:
            value = struct.unpack("<f", slice_bytes)[0]
        except struct.error:
            continue

        candidates.append((offset, slice_bytes, float(value)))

    return candidates


def analyze_cluster_pair(
    block_a: bytes,
    block_b: bytes,
    cluster: list[tuple[int, int, int]],
) -> list[dict[str, object]]:
    """Compare float interpretations for the same diff cluster in two blocks."""
    candidates_a = expand_to_float_candidates(block_a, cluster)
    candidates_b = expand_to_float_candidates(block_b, cluster)
    results: list[dict[str, object]] = []

    for (offset_a, bytes_a, value_a), (offset_b, bytes_b, value_b) in zip(candidates_a, candidates_b):
        if offset_a != offset_b:
            continue

        results.append(
            {
                "offset": offset_a,
                "bytes_a": bytes_a.hex(),
                "bytes_b": bytes_b.hex(),
                "val_a": float(value_a),
                "val_b": float(value_b),
                "delta": abs(float(value_a) - float(value_b)),
            }
        )

    return results


def classify_float(value: float) -> str:
    """Apply a small deterministic label to a float candidate."""
    if not math.isfinite(value):
        return "invalid"

    if abs(value) > 100:
        return "position"
    if -6.5 < value < 6.5:
        return "orientation?"
    if 0 < value < 20:
        return "speed?"
    return "unknown"


def find_best_float_alignment(
    block_a: bytes,
    block_b: bytes,
) -> list[tuple[int, int, list[tuple[int, list[float], list[float], list[float]]]]]:
    """Score each 4-byte base offset by meaningful float-window changes."""
    ranked: list[tuple[int, int, list[tuple[int, list[float], list[float], list[float]]]]] = []

    for base in range(0, 4):
        hits = 0
        candidates: list[tuple[int, list[float], list[float], list[float]]] = []

        for offset in range(base, len(block_a) - 52 + 1, 4):
            try:
                values_a = list(struct.unpack_from("<13f", block_a, offset))
                values_b = list(struct.unpack_from("<13f", block_b, offset))
            except struct.error:
                continue

            if not all(math.isfinite(value) for value in values_a + values_b):
                continue

            deltas = [abs(left - right) for left, right in zip(values_a, values_b)]
            if any(delta > 0.01 for delta in deltas):
                hits += 1
                candidates.append((offset, deltas, values_a, values_b))

        ranked.append((base, hits, candidates))

    ranked.sort(key=lambda item: item[1], reverse=True)
    return ranked


def map_likely_fields(
    candidates: list[tuple[int, list[float], list[float], list[float]]],
) -> list[dict[str, object]]:
    """Apply a small heuristic classifier to changing float candidates."""
    results: list[dict[str, object]] = []

    for offset, deltas, values_a, values_b in candidates:
        for float_index, delta in enumerate(deltas):
            if delta < 0.001:
                continue

            value = values_a[float_index]
            label = "unknown"

            if abs(value) > 100:
                label = "position (x/y/z)"
            elif -6.5 < value < 6.5 and abs(value) > 0.5:
                label = "orientation"
            elif 0 < value < 20:
                label = "speed"

            results.append(
                {
                    "float_index": float_index,
                    "offset": offset + float_index * 4,
                    "value": value,
                    "delta": delta,
                    "label": label,
                    "value_b": values_b[float_index],
                }
            )

    return results


def find_changing_floats(block_a: bytes, block_b: bytes) -> list[dict[str, object]]:
    """Return float windows whose values change meaningfully between captures."""
    results: list[dict[str, object]] = []
    floats_a = unpack_movement_floats(block_a)
    floats_b = unpack_movement_floats(block_b)

    for (offset_a, values_a), (offset_b, values_b) in zip(floats_a, floats_b):
        if offset_a != offset_b:
            continue

        deltas = [abs(left - right) for left, right in zip(values_a, values_b)]
        if any(delta > 0.001 for delta in deltas):
            results.append(
                {
                    "offset": offset_a,
                    "values_a": values_a,
                    "values_b": values_b,
                    "deltas": deltas,
                }
            )

    return results


def dump_movement_floats(payload: bytes) -> list[tuple[int, float]]:
    """Dump the known movement region as 32-bit floats for debugging."""
    movement_block = extract_movement_block(payload)
    floats: list[tuple[int, float]] = []
    for offset in range(0, len(movement_block) - 4 + 1, 4):
        try:
            value = struct.unpack_from("<f", movement_block, offset)[0]
        except struct.error:
            continue
        floats.append((offset + 10, float(value)))
    return floats


def test_player_movement_diff_analysis() -> None:
    """Compare two sniffed player CREATE_OBJECT movement blocks."""
    reference_one = load_reference_payload(FIRST_CAPTURE_PATH)
    reference_two = load_reference_payload(SECOND_CAPTURE_PATH)

    movement_one = extract_movement_block(reference_one)
    movement_two = extract_movement_block(reference_two)

    byte_diffs = diff_movement_blocks(movement_one, movement_two)
    print(f"byte diffs: {len(byte_diffs)}")

    float_changes = find_changing_floats(movement_one, movement_two)
    for change in float_changes[:5]:
        print("\n--- movement candidate ---")
        print(f"offset: {change['offset']}")
        print(f"A: {change['values_a']}")
        print(f"B: {change['values_b']}")
        print(f"deltas: {change['deltas']}")

    assert True


def test_movement_diff_baseline() -> None:
    """Print the number of differing bytes between two CREATE_OBJECT movement blocks."""
    reference_payload = load_reference_payload(FIRST_CAPTURE_PATH)
    server_payload = load_reference_payload(SECOND_CAPTURE_PATH)

    differences = diff_bytes(get_movement_block(reference_payload), get_movement_block(server_payload))

    print("movement diff:", len(differences))

    assert len(differences) > 0


def test_movement_float_align() -> None:
    """Align float values in the movement block without touching verified coord offsets."""
    reference_payload = load_reference_payload(FIRST_CAPTURE_PATH)
    server_payload = load_reference_payload(SECOND_CAPTURE_PATH)

    before = diff_bytes(reference_payload[10:76], server_payload[10:76])
    patched = align_float_values(bytearray(reference_payload), bytearray(server_payload))
    after = diff_bytes(reference_payload[10:76], patched[10:76])

    print("before:", len(before))
    print("after:", len(after))

    assert len(after) < len(before)


def test_movement_constant_patch() -> None:
    """Patch bytes that are constant across multiple sniffed CREATE_OBJECT packets."""
    reference_payload = load_reference_payload(FIRST_CAPTURE_PATH)
    server_payload = load_reference_payload(SECOND_CAPTURE_PATH)
    sniff_set = [
        load_reference_payload(FIRST_CAPTURE_PATH),
        load_reference_payload(SECOND_CAPTURE_PATH),
        load_reference_payload(THIRD_CAPTURE_PATH),
    ]

    before = diff_bytes(reference_payload[10:76], server_payload[10:76])
    constants = find_constant_bytes(sniff_set)
    patched = patch_constant_bytes(bytearray(server_payload), constants)
    after = diff_bytes(reference_payload[10:76], patched[10:76])

    print("before:", len(before))
    print("after:", len(after))

    assert len(after) <= len(before)


def test_movement_final_diff() -> None:
    """Print the remaining byte-level movement diffs between two CREATE_OBJECT packets."""
    reference_payload = load_reference_payload(FIRST_CAPTURE_PATH)
    server_payload = load_reference_payload(SECOND_CAPTURE_PATH)

    differences = print_movement_diffs(reference_payload, server_payload)

    assert len(differences) <= 6


def test_movement_full_patch() -> None:
    """Ensure full movement patching reaches zero diff from the same base template."""
    reference_payload = load_reference_payload(FIRST_CAPTURE_PATH)
    server_payload = build_server_payload_from_same_template(FIRST_CAPTURE_PATH)

    server_payload = align_float_values(bytearray(reference_payload), bytearray(server_payload))
    server_payload = patch_remaining_bytes(bytearray(reference_payload), server_payload)

    differences = diff_bytes(reference_payload[10:76], server_payload[10:76])

    print("final diff:", len(differences))

    assert len(differences) == 0


def test_movement_float_dump_reference() -> None:
    """Print movement floats from the first reference capture."""
    reference_payload = load_reference_payload(FIRST_CAPTURE_PATH)
    for offset, value in dump_movement_floats(reference_payload):
        print(offset, value)


def test_find_movement_alignment() -> None:
    """Rank float alignments for the player CREATE_OBJECT movement block."""
    reference_one = load_reference_payload(FIRST_CAPTURE_PATH)
    reference_two = load_reference_payload(SECOND_CAPTURE_PATH)

    movement_one = extract_movement_block(reference_one)
    movement_two = extract_movement_block(reference_two)

    differences = diff_movement_blocks(movement_one, movement_two)
    clusters = find_diff_clusters(differences)

    print(f"\nTotal diffs: {len(differences)}")
    print(f"Clusters: {len(clusters)}")
    for cluster in clusters:
        print(f"cluster @ {[item[0] for item in cluster]}")

    ranked = find_best_float_alignment(movement_one, movement_two)

    print("\n=== ALIGNMENT RANKING ===")
    for base, hits, _candidates in ranked:
        print(f"base={base} hits={hits}")

    top_base, top_hits, top_candidates = ranked[0]
    print(f"\nBEST base={top_base} hits={top_hits}")

    mapped = map_likely_fields(top_candidates)

    print("\n=== FIELD CANDIDATES ===")
    for candidate in mapped[:10]:
        print(candidate)

    assert True


def test_cluster_float_reconstruction() -> None:
    """Inspect each diff cluster as nearby 4-byte float candidates."""
    reference_one = load_reference_payload(FIRST_CAPTURE_PATH)
    reference_two = load_reference_payload(SECOND_CAPTURE_PATH)

    movement_one = extract_movement_block(reference_one)
    movement_two = extract_movement_block(reference_two)

    differences = diff_movement_blocks(movement_one, movement_two)
    clusters = find_diff_clusters(differences)

    print("\n=== CLUSTER ANALYSIS ===")

    for cluster in clusters:
        print(f"\ncluster: {[index for index, _left, _right in cluster]}")

        results = analyze_cluster_pair(movement_one, movement_two, cluster)
        for result in results:
            label = classify_float(result["val_a"])
            print(
                f"offset={result['offset']} "
                f"{result['bytes_a']}->{result['bytes_b']} "
                f"{result['val_a']:.6f}->{result['val_b']:.6f} "
                f"delta={result['delta']:.6f} "
                f"{label}"
            )

    assert True
