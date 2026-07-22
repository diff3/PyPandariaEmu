#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from types import SimpleNamespace


def test_offline_player_name_query_uses_character_database(monkeypatch):
    from server.modules.handlers.world.opcodes import entities

    captured = {}

    class _Mappings:
        @staticmethod
        def first():
            return {
                "guid": 2,
                "account": 9,
                "name": "Mages",
                "race": 1,
                "gender": 0,
                "class": 8,
                "level": 42,
            }

    class _Result:
        @staticmethod
        def mappings():
            return _Mappings()

    class _Database:
        @staticmethod
        def execute(_statement, parameters):
            assert parameters == {"guid": 2}
            return _Result()

    monkeypatch.setattr(entities, "_decode_name_query_guid", lambda _payload: 2)
    monkeypatch.setattr(entities, "_find_session_by_guid", lambda _session, _guid: None)
    monkeypatch.setattr(entities.DatabaseConnection, "chars", lambda: _Database())
    monkeypatch.setattr(
        entities,
        "_build_name_query_response",
        lambda guid, **fields: captured.update(guid=guid, **fields) or b"name",
    )

    status, responses = entities.handle_name_query(
        SimpleNamespace(
            char_guid=30,
            player_name="Selene",
            realm_id=1,
            global_state=None,
        ),
        SimpleNamespace(name="CMSG_NAME_QUERY", payload=b"query"),
    )

    assert status == 0
    assert responses == [("SMSG_QUERY_PLAYER_NAME_RESPONSE", b"name")]
    assert captured["guid"] == 2
    assert captured["name"] == "Mages"
    assert captured["account_id"] == 9
    assert captured["class_id"] == 8
