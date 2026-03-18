from __future__ import annotations

import json
from typing import Any

from shared.ConfigLoader import ConfigLoader
from shared.Logger import Logger


def _normalize_blacklist(values: Any) -> set[str]:
    if isinstance(values, str):
        items = values.replace(",", "\n").splitlines()
    elif isinstance(values, (list, tuple, set)):
        items = values
    else:
        items = []
    return {
        str(item).strip().upper()
        for item in items
        if str(item).strip()
    }


def _output_cfg(server_key: str) -> dict[str, Any]:
    cfg = ConfigLoader.get_config()
    server_cfg = cfg.get(server_key, {})
    output = server_cfg.get("output", {})
    if not isinstance(output, dict):
        output = {}
    return output


def project_name() -> str:
    cfg = ConfigLoader.get_config()
    return str(cfg.get("project_name", "Unknown")).strip() or "Unknown"


def packet_blacklisted(server_key: str, opcode_name: str | None) -> bool:
    if not opcode_name:
        return False
    return str(opcode_name).strip().upper() in _normalize_blacklist(
        _output_cfg(server_key).get("blacklist", [])
    )


def raw_enabled(server_key: str) -> bool:
    return bool(_output_cfg(server_key).get("raw", False))


def decode_enabled(server_key: str) -> bool:
    return bool(_output_cfg(server_key).get("decode", True))


def dsl_warnings_enabled(server_key: str) -> bool:
    return bool(_output_cfg(server_key).get("dsl_warnings", True))


def should_log_packet(server_key: str, opcode_name: str | None) -> bool:
    return not packet_blacklisted(server_key, opcode_name)


def _to_safe_json(value: Any):
    if isinstance(value, dict):
        return {str(k): _to_safe_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_to_safe_json(v) for v in value]
    if isinstance(value, tuple):
        return [_to_safe_json(v) for v in value]
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, bytearray):
        return bytes(value).hex()
    return value


def log_raw_packet(server_key: str, opcode_name: str | None, label: str, data: bytes) -> None:
    if not raw_enabled(server_key) or packet_blacklisted(server_key, opcode_name):
        return
    Logger.info(f"{label}: {data.hex().upper()}")


def log_decoded_packet(
    server_key: str,
    opcode_name: str | None,
    decoded: dict[str, Any] | None,
    *,
    label: str | None = None,
) -> None:
    if not decode_enabled(server_key) or packet_blacklisted(server_key, opcode_name):
        return
    payload = decoded or {}
    if not payload:
        return
    title = label or str(opcode_name or "<unknown>")
    Logger.success(f"{title}\n{json.dumps(_to_safe_json(payload), indent=2)}")
