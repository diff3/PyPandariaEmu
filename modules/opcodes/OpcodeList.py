#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pathlib
import re

from shared.ConfigLoader import ConfigLoader
from shared.PathUtils import get_protocol_root


def _get_def_dir() -> pathlib.Path | None:
    cfg = ConfigLoader.load_config()
    base = get_protocol_root(
        program=cfg.get("program"),
        expansion=cfg.get("expansion"),
        version=cfg.get("version"),
    )
    if base is None:
        return None
    return base / "data" / "def"


def load_def_files():
    opcode_to_name = {}
    name_to_opcode = {}

    def_dir = _get_def_dir()
    if def_dir is None or not def_dir.is_dir():
        return opcode_to_name, name_to_opcode

    for f in def_dir.glob("*.def"):
        text = f.read_text()

        op_match = re.search(r"opcode:\s*(0x[0-9A-Fa-f]+|\d+)", text)
        name_match = re.search(r"name:\s*([A-Za-z0-9_]+)", text)
        dir_match = re.search(r"direction:\s*(client|server)", text)

        if not op_match or not name_match or not dir_match:
            continue

        opcode_raw = op_match.group(1)
        opcode = int(opcode_raw, 16) if opcode_raw.startswith("0x") else int(opcode_raw)

        base_name = name_match.group(1)
        direction = dir_match.group(1)

        suffix = "_C" if direction == "client" else "_S"
        full_name = f"{base_name}{suffix}"

        opcode_to_name[opcode] = full_name
        name_to_opcode[full_name] = opcode

    return opcode_to_name, name_to_opcode


OPCODE_TO_NAME, NAME_TO_OPCODE = load_def_files()
