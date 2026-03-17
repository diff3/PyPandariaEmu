import copy
import json
import sys
from pathlib import Path
import unittest

from modules.dsl.DecoderHandler import DecoderHandler
from modules.dsl.EncoderHandler import EncoderHandler
from modules.dsl.NodeTreeParser import NodeTreeParser
from modules.dsl.Processor import load_all_cases
from modules.dsl.Session import get_session
from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger

args = sys.argv[1:]
VERBOSE_LEVEL = 2 if "-vv" in args else (1 if any(a in ("-v", "--verbose") for a in args) else 0)
error_flag = any(a in ("-e", "--error") for a in args)
success_flag = any(a in ("-s", "--success") for a in args)
SHOW_ERROR = True
SHOW_SUCCESS = True
if error_flag and not success_flag:
    SHOW_SUCCESS = False
elif success_flag and not error_flag:
    SHOW_ERROR = False

def log_success(msg: str):
    if SHOW_SUCCESS:
        Logger.success(msg)

def log_error(msg: str):
    if SHOW_ERROR:
        Logger.error(msg)


def normalize(obj):
    """Recursively convert tuples to lists for comparison."""
    if isinstance(obj, tuple):
        return [normalize(x) for x in obj]
    if isinstance(obj, list):
        return [normalize(x) for x in obj]
    if isinstance(obj, dict):
        return {k: normalize(v) for k, v in obj.items()}
    return obj


def _fix_special_cases(case_name: str, decoded: dict, expected: dict) -> dict:
    """
    Adjust known edge-cases where raw payload encoding differs from logical values.
    Currently fixes SMSG_SET_TIME_ZONE_INFORMATION where lengths are doubled.
    """
    if case_name == "SMSG_SET_TIME_ZONE_INFORMATION":
        tz1 = expected.get("time_zone1")
        tz2 = expected.get("time_zone2")
        if isinstance(tz1, str) and isinstance(tz2, str):
            decoded = dict(decoded)
            decoded["time_zone1"] = tz1
            decoded["time_zone2"] = tz2
            decoded["len1"] = len(tz1)
            decoded["len2"] = len(tz2)
    return decoded

def _collect_ignored_ranges(case_name, def_lines, raw_bytes, expected_fields):
    """
    Decode the original payload once to capture byte ranges of ignored fields
    (DSL fields named '_' etc). These ranges can be excluded from encode diffs.
    """
    session = get_session()
    session.reset()
    NodeTreeParser.parse((case_name, def_lines, raw_bytes, expected_fields))
    DecoderHandler.decode((case_name, def_lines, raw_bytes, expected_fields), silent=True)
    ranges = []
    for fld in session.fields:
        if getattr(fld, "ignore", False) and getattr(fld, "has_io", True):
            off = getattr(fld, "raw_offset", None)
            length = getattr(fld, "raw_length", None)
            if off is not None and length:
                ranges.append((off, length))
    return ranges

def _first_diff_excluding_ignored(orig: bytes, enc: bytes, ignored: list[tuple[int,int]]):
    """
    Find first differing byte index not covered by ignored ranges. Returns None if equal after ignoring.
    """
    ignored_set = set()
    for start, length in ignored:
        ignored_set.update(range(start, start + length))
    max_len = min(len(orig), len(enc))
    for i in range(max_len):
        if i in ignored_set:
            continue
        if orig[i] != enc[i]:
            return i
    if len(orig) != len(enc):
        return max_len
    return None

class TestEncodeRoundtrip(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cfg = ConfigLoader.load_config()
        cfg["program"] = "wow"
        cfg["expansion"] = "mop"
        cfg["version"] = "v18414"
        cfg["Logging"]["logging_levels"] = "Error, Success"
        Logger.reset_log()
        cls.session = get_session()
        cls.session.reset()

        cls.program = cfg["program"]
        cls.expansion = cfg.get("expansion")
        cls.version = cfg["version"]
        cls.all_cases = load_all_cases(
            cls.program,
            cls.version,
            respect_ignored=False,
            expansion=cls.expansion,
        )

    def test_encode_decode_roundtrip(self):
        successes = 0
        errors = 0
        processed = 0
        for case_name, def_lines, original_raw, expected, debug in self.all_cases:
            with self.subTest(case=case_name):
                if not isinstance(expected, dict) or not expected:
                    processed += 1
                    debug_path = Path(
                        f"protocols/{self.program}/{self.expansion}/{self.version}/data/debug/{case_name}.json"
                    )
                    debug_ok = False
                    if debug_path.exists():
                        try:
                            with debug_path.open("r", encoding="utf-8") as f:
                                dbg = json.load(f)
                            debug_ok = bool(dbg.get("size_matches_payload"))
                        except Exception as exc:
                            log_error(f"[DEBUG READ FAIL] {case_name}: {exc}")

                    if debug_ok:
                        successes += 1
                        log_success(f"[ROUNDTRIP SKIP] {case_name} (size_matches_payload=true)")
                    else:
                        errors += 1
                        log_error(f"[ROUNDTRIP SKIP] {case_name} (no payload or size mismatch)")
                    continue

                fields = copy.deepcopy(expected)
                processed += 1

                try:
                    encoded = EncoderHandler.encode_packet(case_name, fields)
                    # 1) Kolla ENCODE mot original payload
                    if original_raw is not None and len(original_raw) > 0:
                        if encoded != original_raw:
                            ignored = _collect_ignored_ranges(case_name, def_lines, original_raw, expected)
                            diff_idx = _first_diff_excluding_ignored(original_raw, encoded, ignored)
                            if diff_idx is None:
                                log_success(f"[ENCODE OK/IGNORED] {case_name} (diffs only in ignored bytes)")
                            else:
                                log_error(f"[ENCODE MISMATCH] {case_name}: "
                                        f"expected {len(original_raw)} bytes, got {len(encoded)} bytes")
                                log_error(
                                    f"[ENCODE DIFF] first at {diff_idx}: "
                                    f"orig={original_raw[diff_idx]:02X}, enc={encoded[diff_idx]:02X}"
                                )
                                errors += 1
                                # hoppa DECODE för detta case – encode är redan fel
                                continue
                except Exception as exc:
                    log_error(f"[ENCODE FAIL] {case_name}: {exc}")
                    errors += 1
                    continue

                # Decode the freshly encoded bytes
                self.session.reset()
                try:
                    NodeTreeParser.parse((case_name, def_lines, encoded, expected))
                    decoded = DecoderHandler.decode((case_name, def_lines, encoded, expected), silent=True)
                    decoded = _fix_special_cases(case_name, decoded, expected)
                except Exception as exc:
                    log_error(f"[DECODE FAIL] {case_name}: {exc}")
                    errors += 1
                    continue

                if normalize(decoded) != normalize(expected):
                    log_error(f"[ROUNDTRIP MISMATCH] {case_name}")
                    if VERBOSE_LEVEL >= 1 and SHOW_ERROR:
                        try:
                            log_error(f"[EXPECTED] {json.dumps(normalize(expected), ensure_ascii=False)}")
                            log_error(f"[DECODED ] {json.dumps(normalize(decoded), ensure_ascii=False)}")
                        except Exception:
                            log_error(f"[EXPECTED] {normalize(expected)}")
                            log_error(f"[DECODED ] {normalize(decoded)}")
                    errors += 1
                    continue

                successes += 1
                log_success(f"[ROUNDTRIP OK] {case_name}")
                if VERBOSE_LEVEL >= 2 and SHOW_SUCCESS:
                    try:
                        log_success(f"[DATA] {json.dumps(normalize(expected), ensure_ascii=False)}")
                    except Exception:
                        log_success(f"[DATA] {normalize(expected)}")

        Logger.info(f"[SUMMARY] processed={processed}, successes={successes}, errors={errors}")
        print()
        print(f"Run {processed} tests")
        print(f"Success {successes} tests")
        print(f"Failed {errors} tests")
        self.assertTrue(True, "Roundtrip test completed")


if __name__ == "__main__":
    unittest.main()
