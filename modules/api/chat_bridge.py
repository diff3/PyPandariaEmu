#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

from shared.Logger import Logger
from shared.PathUtils import get_data_root
from server.modules.handlers.world.chat.codec import encode_skyfire_messagechat_system_payload
from server.modules.handlers.world.chat.codec import (
    CHAT_MSG_SAY,
    CHAT_MSG_WHISPER,
    CHAT_MSG_WHISPER_INFORM,
    encode_messagechat_payload,
)
from server.modules.handlers.world.state.runtime import dispatch_responses_to_sessions, iter_in_world_sessions

_RUNTIME_DIRNAME = "api_bridge"
_EVENTS_FILE = "chat_events.jsonl"
_COMMANDS_FILE = "chat_commands.jsonl"
_STATUS_FILE = "chat_status.json"
_MAX_FILE_EVENTS = 1000


def _normalize_text(value: Any, *, limit: int = 512) -> str:
    text = str(value or "").strip()
    if len(text) > int(limit):
        return text[: int(limit)]
    return text


def _format_external_chat_message(message: str, *, author: str = "", source: str = "") -> str:
    body = _normalize_text(message, limit=400)
    label = _normalize_text(source, limit=32) or "External"
    speaker = _normalize_text(author, limit=64)
    if speaker:
        return f"[{label}] {speaker}: {body}"
    return f"[{label}] {body}"


class ChatBridgeRuntime:
    def __init__(self) -> None:
        self._lock = threading.Lock()

    def runtime_dir(self) -> Path:
        runtime_dir = get_data_root() / "runtime" / _RUNTIME_DIRNAME
        runtime_dir.mkdir(parents=True, exist_ok=True)
        return runtime_dir

    def events_path(self) -> Path:
        return self.runtime_dir() / _EVENTS_FILE

    def commands_path(self) -> Path:
        return self.runtime_dir() / _COMMANDS_FILE

    def status_path(self) -> Path:
        return self.runtime_dir() / _STATUS_FILE

    def reset(self) -> None:
        for path in (self.events_path(), self.commands_path(), self.status_path()):
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    def clear_commands(self) -> int:
        """Discard commands left from an earlier WorldServer process."""
        path = self.commands_path()
        count = len(self._read_jsonl(path))
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return count

    def clear_events(self) -> int:
        """Begin each WorldServer run with an unambiguous chat history."""
        path = self.events_path()
        count = len(self._read_jsonl(path))
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return count

    def _append_jsonl(self, path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=True) + "\n")

    def _read_jsonl(self, path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        out: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            raw = str(line or "").strip()
            if not raw:
                continue
            try:
                payload = json.loads(raw)
            except Exception:
                continue
            if isinstance(payload, dict):
                out.append(payload)
        return out

    def _write_json_atomic(self, path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
        temporary.replace(path)

    def record_event(
        self,
        *,
        channel: str,
        player_name: str,
        message: str,
        target_name: str = "",
        map_id: int = 0,
        char_guid: int = 0,
        direction: str = "incoming",
    ) -> dict[str, Any] | None:
        normalized_message = _normalize_text(message, limit=400)
        normalized_player = _normalize_text(player_name, limit=64)
        if not normalized_message or not normalized_player:
            return None
        event = {
            "id": int(time.time_ns()),
            "channel": _normalize_text(channel, limit=24).lower() or "say",
            "player_name": normalized_player,
            "message": normalized_message,
            "target_name": _normalize_text(target_name, limit=64),
            "map_id": int(map_id or 0),
            "char_guid": int(char_guid or 0),
            "direction": _normalize_text(direction, limit=16) or "incoming",
            "created_at": time.time(),
        }
        self._append_jsonl(self.events_path(), event)
        self._trim_events_file()
        Logger.info(
            "[ChatAPI] event id=%s channel=%s player=%s target=%s",
            event["id"],
            event["channel"],
            event["player_name"],
            event["target_name"] or "-",
        )
        return event

    def _trim_events_file(self) -> None:
        path = self.events_path()
        rows = self._read_jsonl(path)
        if len(rows) <= _MAX_FILE_EVENTS:
            return
        rows = rows[-_MAX_FILE_EVENTS:]
        with self._lock:
            path.write_text(
                "".join(json.dumps(row, ensure_ascii=True) + "\n" for row in rows),
                encoding="utf-8",
            )

    def get_events(self, *, after_id: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        normalized_after = int(after_id or 0)
        normalized_limit = max(1, min(int(limit or 100), 200))
        events = [
            row
            for row in self._read_jsonl(self.events_path())
            if int(row.get("id", 0) or 0) > normalized_after
        ]
        return events[:normalized_limit]

    def publish_status_snapshot(self) -> dict[str, Any]:
        players = []
        for session in iter_in_world_sessions():
            players.append(
                {
                    "player_name": str(getattr(session, "player_name", "") or ""),
                    "char_guid": int(getattr(session, "char_guid", 0) or 0),
                    "map_id": int(getattr(session, "map_id", 0) or 0),
                    "zone_id": int(
                        getattr(session, "zone_id", 0)
                        or getattr(session, "zone", 0)
                        or 0
                    ),
                }
            )
        players.sort(key=lambda item: (item["player_name"].lower(), item["char_guid"]))
        payload = {
            "updated_at": time.time(),
            "players": players,
        }
        self._write_json_atomic(self.status_path(), payload)
        return payload

    def list_players(self) -> list[dict[str, Any]]:
        path = self.status_path()
        if not path.exists():
            return []
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return []
        players = payload.get("players")
        return list(players) if isinstance(players, list) else []

    def queue_command(self, *, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        command = {
            "id": int(time.time_ns()),
            "kind": str(kind or "").strip(),
            "payload": dict(payload or {}),
            "created_at": time.time(),
        }
        self._append_jsonl(self.commands_path(), command)
        Logger.info("[ChatAPI] queued command id=%s kind=%s", command["id"], command["kind"])
        return command

    def read_commands(self, *, after_id: int = 0) -> list[dict[str, Any]]:
        normalized_after = int(after_id or 0)
        return [
            row
            for row in self._read_jsonl(self.commands_path())
            if int(row.get("id", 0) or 0) > normalized_after
        ]

    def broadcast_external_message(
        self,
        *,
        message: str,
        author: str = "",
        source: str = "Discord",
    ) -> dict[str, Any]:
        return self.queue_command(
            kind="world_broadcast",
            payload={
                "message": _normalize_text(message, limit=400),
                "author": _normalize_text(author, limit=64),
                "source": _normalize_text(source, limit=32) or "Discord",
            },
        )

    def whisper_external_message(
        self,
        *,
        target_name: str,
        message: str,
        author: str = "",
        source: str = "Discord",
    ) -> dict[str, Any]:
        return self.queue_command(
            kind="whisper",
            payload={
                "target_name": _normalize_text(target_name, limit=64),
                "message": _normalize_text(message, limit=400),
                "author": _normalize_text(author, limit=64),
                "source": _normalize_text(source, limit=32) or "Discord",
            },
        )

    def player_message(
        self,
        *,
        sender_guid: int = 0,
        sender_name: str,
        chat_type: str,
        message: str,
        target_name: str = "",
    ) -> dict[str, Any]:
        normalized_type = _normalize_text(chat_type, limit=16).lower()
        if normalized_type not in {"say", "world", "whisper"}:
            raise ValueError("invalid chat type")
        normalized_sender = _normalize_text(sender_name, limit=64)
        normalized_message = _normalize_text(message, limit=400)
        normalized_target = _normalize_text(target_name, limit=64)
        if not normalized_sender:
            raise ValueError("sender name is required")
        if not normalized_message:
            raise ValueError("message is required")
        if normalized_type == "whisper" and not normalized_target:
            raise ValueError("target name is required")
        return self.queue_command(
            kind="player_chat",
            payload={
                "sender_guid": max(0, int(sender_guid or 0)),
                "sender_name": normalized_sender,
                "chat_type": normalized_type,
                "target_name": normalized_target,
                "message": normalized_message,
            },
        )

    @staticmethod
    def _online_session(player_name: str):
        key = _normalize_text(player_name, limit=64).casefold()
        if not key:
            return None
        for session in iter_in_world_sessions():
            if str(getattr(session, "player_name", "") or "").strip().casefold() == key:
                return session
        return None

    def dispatch_player_message(
        self,
        *,
        sender_guid: int = 0,
        sender_name: str,
        chat_type: str,
        message: str,
        target_name: str = "",
    ) -> bool:
        sender = self._online_session(sender_name)
        normalized_message = _normalize_text(message, limit=400)
        resolved_sender_guid = int(getattr(sender, "char_guid", 0) or 0)
        if resolved_sender_guid <= 0:
            resolved_sender_guid = max(0, int(sender_guid or 0))
        if resolved_sender_guid <= 0:
            try:
                from sqlalchemy import text
                from server.modules.database.DatabaseConnection import DatabaseConnection

                DatabaseConnection.initialize()
                row = DatabaseConnection.chars().execute(
                    text(
                        "SELECT guid FROM characters "
                        "WHERE LOWER(name)=LOWER(:name) AND deleteDate IS NULL LIMIT 1"
                    ),
                    {"name": str(sender_name)},
                ).mappings().first()
                resolved_sender_guid = int((row or {}).get("guid", 0) or 0)
            except Exception as exc:
                Logger.warning(
                    "[ChatAPI] sender identity lookup failed name=%s err=%s",
                    sender_name,
                    exc,
                )
        if resolved_sender_guid <= 0 or not normalized_message:
            return False
        language = 0
        if sender is not None:
            language = int(
                getattr(sender, "current_language", 0)
                or getattr(sender, "language", 0)
                or 0
            )
        normalized_type = _normalize_text(chat_type, limit=16).lower()
        if normalized_type in {"say", "world"}:
            payload = encode_messagechat_payload(
                chat_type=CHAT_MSG_SAY,
                language=language,
                sender_guid=resolved_sender_guid,
                sender_name=str(getattr(sender, "player_name", "") or sender_name),
                target_guid=0,
                target_name="",
                message=normalized_message,
            )
            targets = iter_in_world_sessions()
            if normalized_type == "say" and sender is not None:
                from server.modules.handlers.world.chat.router import chat_router

                targets = list(chat_router.get_targets(sender, "say")) or [sender]
            dispatch_responses_to_sessions(targets, [("SMSG_MESSAGECHAT", payload)])
            self.record_event(
                channel="say",
                player_name=str(getattr(sender, "player_name", "") or sender_name),
                message=normalized_message,
                map_id=int(getattr(sender, "map_id", 0) or 0),
                char_guid=resolved_sender_guid,
                direction="outgoing",
            )
            return True
        if normalized_type != "whisper":
            return False
        target = self._online_session(target_name)
        if target is None:
            return False
        target_guid = int(getattr(target, "char_guid", 0) or 0)
        sender_label = str(getattr(sender, "player_name", "") or sender_name)
        target_label = str(getattr(target, "player_name", "") or target_name)
        recipient_payload = encode_messagechat_payload(
            chat_type=CHAT_MSG_WHISPER,
            language=language,
            sender_guid=resolved_sender_guid,
            sender_name=sender_label,
            target_guid=target_guid,
            target_name=target_label,
            message=normalized_message,
        )
        echo_payload = encode_messagechat_payload(
            chat_type=CHAT_MSG_WHISPER_INFORM,
            language=language,
            sender_guid=resolved_sender_guid,
            sender_name=sender_label,
            target_guid=target_guid,
            target_name=target_label,
            message=normalized_message,
        )
        dispatch_responses_to_sessions([target], [("SMSG_MESSAGECHAT", recipient_payload)])
        if sender is not None:
            dispatch_responses_to_sessions([sender], [("SMSG_MESSAGECHAT", echo_payload)])
        self.record_event(
            channel="whisper",
            player_name=sender_label,
            message=normalized_message,
            target_name=target_label,
            map_id=int(getattr(target, "map_id", 0) or 0),
            char_guid=resolved_sender_guid,
            direction="outgoing",
        )
        return True

    def dispatch_world_broadcast(self, *, message: str, author: str = "", source: str = "Discord") -> int:
        # API transport metadata must never leak into the in-game presentation.
        text = _normalize_text(message, limit=400)
        payload = encode_skyfire_messagechat_system_payload(text)
        targets = iter_in_world_sessions()
        dispatch_responses_to_sessions(targets, [("SMSG_MESSAGECHAT", payload)])
        if targets:
            self.record_event(
                channel="world",
                player_name="Server",
                message=text,
                direction="outgoing",
            )
        return len(targets)

    def dispatch_whisper(self, *, target_name: str, message: str, author: str = "", source: str = "Discord") -> bool:
        normalized_target = _normalize_text(target_name, limit=64)
        if not normalized_target:
            return False
        match = None
        normalized_key = normalized_target.lower()
        for session in iter_in_world_sessions():
            if str(getattr(session, "player_name", "") or "").strip().lower() == normalized_key:
                match = session
                break
        if match is None:
            return False
        text = _normalize_text(message, limit=400)
        payload = encode_skyfire_messagechat_system_payload(text)
        dispatch_responses_to_sessions([match], [("SMSG_MESSAGECHAT", payload)])
        self.record_event(
            channel="system whisper",
            player_name="Server",
            message=text,
            target_name=str(getattr(match, "player_name", "") or normalized_target),
            map_id=int(getattr(match, "map_id", 0) or 0),
            direction="outgoing",
        )
        return True


chat_bridge_runtime = ChatBridgeRuntime()
