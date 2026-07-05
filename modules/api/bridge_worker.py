#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import threading
import time

from shared.Logger import Logger
from shared.ConfigLoader import ConfigLoader
from server.modules.api.chat_bridge import chat_bridge_runtime

_THREAD = None
_STOP = threading.Event()


def _api_bridge_enabled() -> bool:
    config = ConfigLoader.get_config()
    section = dict(config.get("Api") or {})
    return bool(section.get("EnableBridge", True))


def _dispatch_command(command: dict) -> None:
    kind = str(command.get("kind", "") or "").strip().lower()
    payload = dict(command.get("payload") or {})
    if kind == "world_broadcast":
        delivered = chat_bridge_runtime.dispatch_world_broadcast(
            message=str(payload.get("message", "") or ""),
            author=str(payload.get("author", "") or ""),
            source=str(payload.get("source", "Discord") or "Discord"),
        )
        Logger.info("[ChatAPI] processed command id=%s kind=%s delivered=%s", command.get("id"), kind, delivered)
        return
    if kind == "whisper":
        ok = chat_bridge_runtime.dispatch_whisper(
            target_name=str(payload.get("target_name", "") or ""),
            message=str(payload.get("message", "") or ""),
            author=str(payload.get("author", "") or ""),
            source=str(payload.get("source", "Discord") or "Discord"),
        )
        Logger.info("[ChatAPI] processed command id=%s kind=%s ok=%s", command.get("id"), kind, int(bool(ok)))
        return
    Logger.warning("[ChatAPI] ignoring unknown command id=%s kind=%s", command.get("id"), kind)


def _worker_loop() -> None:
    last_command_id = 0
    next_status_at = 0.0
    while not _STOP.is_set():
        try:
            now = time.time()
            if now >= next_status_at:
                chat_bridge_runtime.publish_status_snapshot()
                next_status_at = now + 1.0
            commands = chat_bridge_runtime.read_commands(after_id=last_command_id)
            for command in commands:
                _dispatch_command(command)
                last_command_id = max(last_command_id, int(command.get("id", 0) or 0))
        except Exception as exc:
            Logger.warning("[ChatAPI] bridge loop failed: %s", exc)
        _STOP.wait(0.5)


def start_world_api_bridge() -> bool:
    global _THREAD
    if not _api_bridge_enabled():
        Logger.info("[ChatAPI] bridge disabled")
        return False
    if _THREAD is not None and _THREAD.is_alive():
        return True
    _STOP.clear()
    _THREAD = threading.Thread(target=_worker_loop, daemon=True, name="world-api-bridge")
    _THREAD.start()
    Logger.info("[ChatAPI] bridge worker started")
    return True


def stop_world_api_bridge() -> None:
    global _THREAD
    _STOP.set()
    thread = _THREAD
    _THREAD = None
    if thread is not None and thread.is_alive():
        thread.join(timeout=2.0)
    Logger.info("[ChatAPI] bridge worker stopped")

