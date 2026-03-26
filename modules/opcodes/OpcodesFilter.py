# modules/utils/opcode_filter.py

import re

def _normalize(value):
    """Normalize config entries such as '0x12B3', '12B3', '4725', 'SMSG_XYZ', etc."""
    if isinstance(value, int):
        return value

    value = value.strip()

    # Hex forms
    if value.lower().startswith("0x"):
        try:
            return int(value, 16)
        except ValueError:
            return value

    # Decimal opcode
    if value.isdigit():
        return int(value)

    # Hex without 0x (e.g. "12ab")
    if re.fullmatch(r"[0-9a-fA-F]+", value):
        try:
            return int(value, 16)
        except ValueError:
            return value

    # Symbolic opcode name
    return value


def _match(value, rule):
    if value is None or rule is None:
        return False

    # convert both to string for comparison
    value = str(value).upper()
    rule = str(rule).upper()

    # wildcard
    if "*" in rule:
        from fnmatch import fnmatch
        return fnmatch(value, rule)

    # exact match
    return value == rule


def _match(value, rule):
    if value is None or rule is None:
        return False

    value = str(value).upper()
    rule = str(rule).upper()

    if "*" in rule:
        from fnmatch import fnmatch
        return fnmatch(value, rule)

    return value == rule


def filter_opcode(name, code, cfg):
    whitelist = cfg.get("WhiteListedOpcodes", [])
    blacklist = cfg.get("BlackListedOpcodes", [])

    if isinstance(whitelist, (str, int)):
        whitelist = [whitelist]
    if isinstance(blacklist, (str, int)):
        blacklist = [blacklist]

    name_u = str(name).upper()

    # 1) BLACKLIST ALWAYS WINS
    for b in blacklist:
        if _match(name_u, b) or _match(code, b):
            return False

    # 2) WHITELIST-LOGIK
    if not whitelist:
        # ingen whitelist → allt (som inte är blacklisted) är OK
        return True

    if len(whitelist) == 1 and str(whitelist[0]).lower() == "all":
        return True

    for w in whitelist:
        if _match(name_u, w) or _match(code, w):
            return True

    return False