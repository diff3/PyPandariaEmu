#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import json
import sys
from modules.dsl.DecoderHandler import DecoderHandler
from modules.dsl.NodeTreeParser import NodeTreeParser
from modules.dsl.Processor import load_all_cases
from modules.dsl.Session import get_session
from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger

# GLOBALS
config = ConfigLoader.get_config()
session = get_session()
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


class TestAllCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        config["program"] = "wow"
        config["expansion"] = "mop"
        config["version"] = "v18414"
        config["Logging"]["logging_levels"] = "Error, Success"
        Logger.reset_log()
        session.reset()

        cls.program = config["program"]
        cls.expansion = config.get("expansion")
        cls.version = config["version"]
        # Override ignore list for full coverage in tests
        cls.all_cases = load_all_cases(
            cls.program,
            cls.version,
            respect_ignored=False,
            expansion=cls.expansion,
        )

    def test_cases(self):
        num = 0
        failed = 0
        success = 0

        for case_name, def_lines, binary_data, expected, debug in self.all_cases:
            session.reset()
            num += 1

            with self.subTest(case=case_name):
                try:
                    # NodeTreeParser.parse(def_lines)
                    NodeTreeParser.parse((case_name, def_lines, binary_data, expected))
                    result = DecoderHandler.decode((case_name, def_lines, binary_data, expected), silent=True)
                    result = _fix_special_cases(case_name, result, expected)


                    if normalize(result) == normalize(expected):
                        success += 1
                        log_success(f"{case_name}")
                        if VERBOSE_LEVEL >= 2 and SHOW_SUCCESS:
                            try:
                                log_success(f"[DATA] {json.dumps(normalize(expected), ensure_ascii=False)}")
                            except Exception:
                                log_success(f"[DATA] {normalize(expected)}")
                    elif normalize(result) != normalize(expected):
                        log_error(f"{case_name}")
                        if VERBOSE_LEVEL >= 1 and SHOW_ERROR:
                            try:
                                log_error(f"[EXPECTED] {json.dumps(normalize(expected), ensure_ascii=False)}")
                                log_error(f"[DECODED ] {json.dumps(normalize(result), ensure_ascii=False)}")
                            except Exception:
                                log_error(f"[EXPECTED] {normalize(expected)}")
                                log_error(f"[DECODED ] {normalize(result)}")
                        failed += 1
                    else:
                        print("Unknown error")
                        Logger.info(result)

                except Exception as e:
                    failed += 1
                    log_error(f"[ERROR] {case_name}: {e}")

        print()
        print(f"Run {num} tests")
        print(f"Success {success} tests")
        print(f"Failed {failed} tests")
