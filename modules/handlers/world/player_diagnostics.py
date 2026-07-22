#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Temporary structured diagnostics for Player lifecycle ownership."""

from __future__ import annotations

import json
import time

from shared.ConfigLoader import ConfigLoader
from shared.Logger import Logger
from server.modules.handlers.world.runtime.player_store import resolve_player_runtime


def enabled() -> bool:
    config = ConfigLoader.get_config() or {}
    return bool(dict(config.get("World") or {}).get("DebugPlayerLifecycle", False))


def log_player_event(event: str, session, **fields) -> None:
    if not enabled() or session is None:
        return
    player = resolve_player_runtime(session)
    payload = {
        "event": str(event),
        "server_time": round(time.time(), 6),
        "server_tick_ns": time.monotonic_ns(),
        "player_guid": int(player.character_guid),
        "map_id": int(player.map_id),
        "instance_id": int(player.instance_id),
        "phase": int(getattr(session, "phase_mask", 0) or 0),
        "position": [
            round(float(player.x), 4),
            round(float(player.y), 4),
            round(float(player.z), 4),
        ],
        "session_queue_depth": int(getattr(session, "_packet_queue_depth", 0) or 0),
    }
    payload.update(fields)
    Logger.info("[PLAYER_LIFECYCLE] %s", json.dumps(payload, sort_keys=True))
