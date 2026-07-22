#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from shared.ConfigLoader import ConfigLoader
from shared.Logger import Logger
from server.modules.api.chat_bridge import chat_bridge_runtime


API_DOCUMENTATION = {
    "name": "PyPandaria API",
    "version": "0.2",
    "authentication": {
        "configuration": "Api.Token",
        "headers": ["Authorization: Bearer <token>", "X-API-Token: <token>"],
    },
    "routes": [
        {
            "method": "GET",
            "path": "/api",
            "description": "Returns API documentation",
        },
        {
            "method": "GET",
            "path": "/api/health",
            "description": "Health check",
        },
        {
            "method": "GET",
            "path": "/api/chat/players",
            "description": "Returns online players",
        },
        {
            "method": "GET",
            "path": "/api/chat/events",
            "description": "Returns chat events",
            "query": {
                "after_id": "integer",
                "limit": "integer",
            },
        },
        {
            "method": "POST",
            "path": "/api/chat/world",
            "description": "Broadcast external chat message",
            "body": {
                "author": "string",
                "source": "string",
                "message": "string",
            },
        },
        {
            "method": "POST",
            "path": "/api/chat/whisper",
            "description": "Send external whisper",
            "body": {
                "target_name": "string",
                "author": "string",
                "source": "string",
                "message": "string",
            },
        },
        {
            "method": "POST",
            "path": "/api/chat/player",
            "description": "Send chat using a trusted player identity",
            "body": {
                "sender_guid": "character guid",
                "sender_name": "character name",
                "chat_type": "say, world or whisper",
                "target_name": "whisper recipient",
                "message": "string",
            },
        },
        {
            "method": "POST",
            "path": "/api/mail/system",
            "description": "Send persisted system mail to a character",
            "body": {
                "recipient": "character name or guid",
                "subject": "string",
                "body": "string",
            },
        },
        {
            "method": "POST",
            "path": "/api/mail/player",
            "description": "Send persisted player mail to a character",
            "body": {
                "sender_guid": "character guid",
                "recipient": "character name or guid",
                "subject": "string",
                "body": "string",
            },
        },
    ],
}


def _api_config() -> dict:
    config = ConfigLoader.get_config()
    section = dict(config.get("Api") or {})
    return {
        "enabled": bool(section.get("EnableServer", True)),
        "host": str(section.get("Host", "127.0.0.1") or "127.0.0.1"),
        "port": int(section.get("Port", 8090) or 8090),
        "token": str(section.get("Token", "") or ""),
    }


def _write_json(handler: BaseHTTPRequestHandler, status: int, payload: dict) -> None:
    body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    handler.send_response(int(status))
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _unauthorized(handler: BaseHTTPRequestHandler, token: str) -> bool:
    token = str(token or "")
    if not token:
        return False
    header = str(handler.headers.get("Authorization", "") or "").strip()
    alt = str(handler.headers.get("X-API-Token", "") or "").strip()
    if header == f"Bearer {token}" or alt == token:
        return False
    _write_json(handler, 401, {"error": "unauthorized"})
    return True


def _read_json(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length", "0") or 0)
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    if not raw:
        return {}
    decoded = json.loads(raw.decode("utf-8"))
    return decoded if isinstance(decoded, dict) else {}


def build_handler(token: str):
    class _WorldApiHandler(BaseHTTPRequestHandler):
        server_version = "PyPandariaApi/0.2"

        def log_message(self, format: str, *args) -> None:
            Logger.info("[ApiServer] " + str(format), *args)

        def do_GET(self) -> None:
            if _unauthorized(self, token):
                return
            parsed = urlparse(self.path)
            if parsed.path == "/api":
                payload = dict(API_DOCUMENTATION)
                payload["authentication_required"] = bool(token)
                _write_json(self, 200, payload)
                return
            if parsed.path == "/api/health":
                _write_json(self, 200, {"ok": True, "service": "api-server"})
                return
            if parsed.path == "/api/chat/players":
                _write_json(self, 200, {"players": chat_bridge_runtime.list_players()})
                return
            if parsed.path == "/api/chat/events":
                query = parse_qs(parsed.query)
                after_id = int((query.get("after_id") or ["0"])[0] or 0)
                limit = int((query.get("limit") or ["100"])[0] or 100)
                _write_json(self, 200, {"events": chat_bridge_runtime.get_events(after_id=after_id, limit=limit)})
                return
            _write_json(self, 404, {"error": "not_found"})

        def do_POST(self) -> None:
            if _unauthorized(self, token):
                return
            parsed = urlparse(self.path)
            payload = _read_json(self)
            if parsed.path == "/api/chat/world":
                command = chat_bridge_runtime.broadcast_external_message(
                    message=str(payload.get("message", "") or ""),
                    author=str(payload.get("author", "") or ""),
                    source=str(payload.get("source", "Discord") or "Discord"),
                )
                _write_json(self, 202, {"ok": True, "queued": command})
                return
            if parsed.path == "/api/chat/whisper":
                command = chat_bridge_runtime.whisper_external_message(
                    target_name=str(payload.get("target_name", "") or ""),
                    message=str(payload.get("message", "") or ""),
                    author=str(payload.get("author", "") or ""),
                    source=str(payload.get("source", "Discord") or "Discord"),
                )
                _write_json(self, 202, {"ok": True, "queued": command})
                return
            if parsed.path == "/api/chat/player":
                try:
                    command = chat_bridge_runtime.player_message(
                        sender_guid=int(payload.get("sender_guid", 0) or 0),
                        sender_name=str(payload.get("sender_name", "") or ""),
                        chat_type=str(payload.get("chat_type", "") or ""),
                        target_name=str(payload.get("target_name", "") or ""),
                        message=str(payload.get("message", "") or ""),
                    )
                except ValueError as exc:
                    _write_json(self, 400, {"error": str(exc)})
                    return
                _write_json(self, 202, {"ok": True, "queued": command})
                return
            if parsed.path == "/api/mail/system":
                from server.modules.database.DatabaseConnection import DatabaseConnection
                from server.modules.mail.api import MailAPI
                try:
                    DatabaseConnection.initialize()
                    mail = MailAPI.send_system(
                        payload.get("recipient", ""),
                        str(payload.get("subject", "") or ""),
                        str(payload.get("body", "") or ""),
                    )
                except ValueError as exc:
                    _write_json(self, 400, {"error": str(exc)})
                    return
                _write_json(self, 201, {"ok": True, "mail_id": int(mail.id)})
                return
            if parsed.path == "/api/mail/player":
                from server.modules.database.DatabaseConnection import DatabaseConnection
                from server.modules.mail.api import MailAPI
                try:
                    DatabaseConnection.initialize()
                    sender_guid = int(payload.get("sender_guid", 0) or 0)
                    if sender_guid <= 0:
                        raise ValueError("sender_required")
                    mail = MailAPI.send(
                        payload.get("recipient", ""),
                        str(payload.get("subject", "") or ""),
                        str(payload.get("body", "") or ""),
                        sender_guid=sender_guid,
                    )
                except (TypeError, ValueError) as exc:
                    _write_json(self, 400, {"error": str(exc)})
                    return
                _write_json(self, 201, {"ok": True, "mail_id": int(mail.id)})
                return
            _write_json(self, 404, {"error": "not_found"})

    return _WorldApiHandler


def run_api_server() -> None:
    cfg = _api_config()
    if not cfg["enabled"]:
        Logger.info("[ApiServer] disabled")
        return
    handler = build_handler(cfg["token"])
    server = ThreadingHTTPServer((cfg["host"], cfg["port"]), handler)
    Logger.success("[ApiServer] listening on %s:%s", cfg["host"], cfg["port"])
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            server.shutdown()
        except Exception:
            pass
        server.server_close()
        Logger.info("[ApiServer] stopped")
