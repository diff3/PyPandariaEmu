#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()
