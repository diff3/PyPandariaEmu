#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from server.modules.api.chat_bridge import chat_bridge_runtime
from server.modules.api import bridge_worker
from server.modules.api import server as api_server
from server.modules.handlers.world.state.global_state import global_state
from shared.ConfigLoader import ConfigLoader


class _FakeSession:
    def __init__(self, name: str, guid: int, *, map_id: int = 1, zone_id: int = 12):
        self.player_name = name
        self.char_guid = guid
        self.map_id = map_id
        self.zone = zone_id
        self.login_state = "IN_WORLD"
        self.sent = []

    def send_response(self, responses):
        self.sent.append(list(responses))


class ChatApiTest(unittest.TestCase):
    def setUp(self):
        self.original_sessions = set(global_state.sessions)
        self.original_world = set(global_state.chat_channels.get("world", set()) or ())
        global_state.sessions.clear()
        global_state.chat_channels["world"] = set()
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        ConfigLoader.set_runtime_config(
            {
                "Logging": {
                    "date_format": "%Y-%m-%d %H:%M:%S",
                    "write_to_log": False,
                    "log_file": "test.log",
                },
                "paths": {
                    "root": self.tempdir.name,
                    "def_dir": "data/def",
                },
                "Api": {
                    "EnableServer": True,
                    "EnableBridge": True,
                    "Host": "127.0.0.1",
                    "Port": 18090,
                    "Token": "",
                },
            }
        )
        chat_bridge_runtime.reset()

    def tearDown(self):
        global_state.sessions.clear()
        global_state.sessions.update(self.original_sessions)
        global_state.chat_channels["world"] = set(self.original_world)
        chat_bridge_runtime.reset()
        bridge_worker.stop_world_api_bridge()
        ConfigLoader.clear_runtime_config()

    def test_record_and_fetch_chat_events(self):
        first = chat_bridge_runtime.record_event(
            channel="say",
            player_name="Alice",
            message="hej",
            map_id=369,
            char_guid=11,
        )
        second = chat_bridge_runtime.record_event(
            channel="whisper",
            player_name="Bob",
            message="psst",
            target_name="Alice",
            map_id=1,
            char_guid=22,
        )
        self.assertGreater(first["id"], 0)
        self.assertGreater(second["id"], first["id"])
        self.assertEqual(chat_bridge_runtime.get_events(after_id=first["id"]), [second])

    def test_publish_and_read_status_snapshot(self):
        alice = _FakeSession("Alice", 1, map_id=369)
        bob = _FakeSession("Bob", 2, map_id=0)
        global_state.sessions.update({alice, bob})
        snapshot = chat_bridge_runtime.publish_status_snapshot()
        self.assertEqual(len(snapshot["players"]), 2)
        players = chat_bridge_runtime.list_players()
        self.assertEqual([entry["player_name"] for entry in players], ["Alice", "Bob"])

    def test_queue_commands_for_separate_api_server(self):
        command = chat_bridge_runtime.broadcast_external_message(
            message="Hello from Discord",
            author="BridgeBot",
            source="Discord",
        )
        rows = chat_bridge_runtime.read_commands(after_id=0)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], command["id"])
        self.assertEqual(rows[0]["kind"], "world_broadcast")

    def test_clear_commands_discards_only_pending_command_queue(self):
        chat_bridge_runtime.record_event(
            channel="say",
            player_name="Alice",
            message="keep event",
        )
        chat_bridge_runtime.publish_status_snapshot()
        chat_bridge_runtime.broadcast_external_message(message="discard command")

        self.assertEqual(chat_bridge_runtime.clear_commands(), 1)
        self.assertEqual(chat_bridge_runtime.read_commands(after_id=0), [])
        self.assertEqual(len(chat_bridge_runtime.get_events(after_id=0)), 1)
        self.assertTrue(chat_bridge_runtime.status_path().exists())

    def test_bridge_startup_discards_commands_from_previous_process(self):
        chat_bridge_runtime.broadcast_external_message(message="stale")

        class _FakeThread:
            def __init__(self, **_kwargs):
                self.started = False

            def start(self):
                self.started = True

            def is_alive(self):
                return self.started

            def join(self, timeout=None):
                self.started = False

        with patch("server.modules.api.bridge_worker.threading.Thread", _FakeThread):
            self.assertTrue(bridge_worker.start_world_api_bridge())

        self.assertEqual(chat_bridge_runtime.read_commands(after_id=0), [])

    def test_bridge_worker_dispatches_world_broadcast(self):
        alice = _FakeSession("Alice", 1)
        global_state.sessions.add(alice)
        command = chat_bridge_runtime.broadcast_external_message(
            message="Hello from Discord",
            author="BridgeBot",
            source="Discord",
        )
        bridge_worker._dispatch_command(command)
        self.assertEqual(alice.sent[0][0][0], "SMSG_MESSAGECHAT")

    def test_api_server_startup_uses_configured_host_and_port(self):
        fake_server = type(
            "FakeHttpServer",
            (),
            {
                "__init__": lambda self, address, handler: setattr(self, "address", address),
                "serve_forever": lambda self: None,
                "shutdown": lambda self: None,
                "server_close": lambda self: None,
            },
        )
        with patch("server.modules.api.server.ThreadingHTTPServer", fake_server):
            with patch("server.modules.api.server.Logger.success") as success:
                api_server.run_api_server()
        success.assert_called_once()

    def _request(
        self,
        method: str,
        path: str,
        *,
        token: str = "",
        body: dict | None = None,
        headers: dict | None = None,
    ):
        handler_class = api_server.build_handler(token)
        handler = object.__new__(handler_class)
        encoded_body = b"" if body is None else json.dumps(body).encode("utf-8")
        handler.path = path
        handler.headers = dict(headers or {})
        if encoded_body:
            handler.headers["Content-Length"] = str(len(encoded_body))
            handler.headers["Content-Type"] = "application/json"
        handler.rfile = io.BytesIO(encoded_body)
        handler.wfile = io.BytesIO()
        response = {"status": None, "headers": {}}
        handler.send_response = lambda status: response.__setitem__("status", status)
        handler.send_header = lambda key, value: response["headers"].__setitem__(key, value)
        handler.end_headers = lambda: None

        getattr(handler, f"do_{method}")()
        payload = json.loads(handler.wfile.getvalue().decode("utf-8"))
        return response["status"], payload

    def test_api_documentation_lists_all_routes(self):
        status, payload = self._request("GET", "/api")

        self.assertEqual(status, 200)
        self.assertEqual(payload["name"], "PyPandaria API")
        self.assertEqual(payload["version"], "0.2")
        self.assertFalse(payload["authentication_required"])
        self.assertEqual(
            {(route["method"], route["path"]) for route in payload["routes"]},
            {
                ("GET", "/api"),
                ("GET", "/api/health"),
                ("GET", "/api/chat/players"),
                ("GET", "/api/chat/events"),
                ("POST", "/api/chat/world"),
                ("POST", "/api/chat/whisper"),
                ("POST", "/api/mail/system"),
            },
        )

    def test_api_documentation_uses_existing_token_authentication(self):
        status, payload = self._request("GET", "/api", token="secret")
        self.assertEqual(status, 401)
        self.assertEqual(payload, {"error": "unauthorized"})

        status, payload = self._request(
            "GET",
            "/api",
            token="secret",
            headers={"Authorization": "Bearer secret"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(payload["authentication_required"])

    def test_existing_api_routes_keep_their_responses(self):
        status, payload = self._request("GET", "/api/health")
        self.assertEqual((status, payload), (200, {"ok": True, "service": "api-server"}))

        status, payload = self._request("GET", "/api/chat/players")
        self.assertEqual((status, payload), (200, {"players": []}))

        status, payload = self._request("GET", "/api/chat/events?after_id=0&limit=10")
        self.assertEqual((status, payload), (200, {"events": []}))

        status, payload = self._request(
            "POST",
            "/api/chat/world",
            body={"author": "Bot", "source": "Test", "message": "World"},
        )
        self.assertEqual(status, 202)
        self.assertTrue(payload["ok"])

        status, payload = self._request(
            "POST",
            "/api/chat/whisper",
            body={
                "target_name": "Alice",
                "author": "Bot",
                "source": "Test",
                "message": "Whisper",
            },
        )
        self.assertEqual(status, 202)
        self.assertTrue(payload["ok"])


if __name__ == "__main__":
    unittest.main()
