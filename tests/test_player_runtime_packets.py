#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Regression coverage for Player-backed packet construction."""

from __future__ import annotations

import struct
import sys
import types


database_module = types.ModuleType(
    "server.modules.database.DatabaseConnection",
)
database_module.DatabaseConnection = type(
    "DatabaseConnection",
    (),
    {
        "get_gameobjects_near": staticmethod(lambda *args, **kwargs: []),
        "get_creatures_near": staticmethod(lambda *args, **kwargs: []),
        "get_areatrigger_teleport": staticmethod(
            lambda *args, **kwargs: None
        ),
    },
)
sys.modules.setdefault(
    "server.modules.database.DatabaseConnection",
    database_module,
)

inventory_module = types.ModuleType("server.modules.game.inventory")
inventory_module.refresh_session_inventory = lambda session: None
inventory_module.persist_session_inventory = lambda session, **kwargs: None
sys.modules.setdefault("server.modules.game.inventory", inventory_module)

characters_module = types.ModuleType(
    "server.modules.handlers.world.characters.characters",
)
characters_module.handle_CMSG_CHAR_CREATE = lambda *args, **kwargs: (0, None)
characters_module.handle_CMSG_CHAR_DELETE = lambda *args, **kwargs: (0, None)
characters_module.handle_CMSG_REORDER_CHARACTERS = (
    lambda *args, **kwargs: (0, None)
)
sys.modules.setdefault(
    "server.modules.handlers.world.characters.characters",
    characters_module,
)

from server.modules.handlers.world.bootstrap.playerobjects import (
    build_server_built_minimal_player_value_update,
    build_server_built_player_create,
)
from server.modules.handlers.world.login.context import WorldLoginContext
from server.modules.handlers.world.login.packets import (
    build_SMSG_LOGIN_VERIFY_WORLD,
    build_SMSG_MOVE_SET_ACTIVE_MOVER,
)
from server.modules.handlers.world.opcodes import login as login_handlers
from server.modules.handlers.world.opcodes import movement as movement_handlers
from server.modules.handlers.world.runtime import Player, get_player_runtime_store
from server.modules.handlers.world.state import runtime as state_runtime
from server.session.world_session import WorldSession


def _packet_session(**overrides):
    values = {
        "player_guid": 0x100000000000002A,
        "world_guid": 0x100000000000002A,
        "char_guid": 42,
        "map_id": 1,
        "instance_id": 0,
        "x": 100.25,
        "y": -200.5,
        "z": 30.75,
        "orientation": 1.25,
        "race": 1,
        "class_id": 1,
        "gender": 0,
        "level": 10,
        "health": 100,
    }
    values.update(overrides)
    session = WorldSession(**values)
    session.movement_state.x = session.x
    session.movement_state.y = session.y
    session.movement_state.z = session.z
    session.movement_state.orientation = session.orientation
    return session


def test_player_create_runtime_path_is_byte_identical_without_override():
    session = _packet_session()
    ctx = WorldLoginContext.from_session(session)
    player = Player.from_session(session)

    assert build_server_built_player_create(
        ctx,
        player,
    ) == build_server_built_player_create(ctx)


def test_player_create_reads_identity_and_geometry_from_runtime_player():
    ctx = WorldLoginContext.from_session(_packet_session())
    player = Player.from_session(
        _packet_session(
            world_guid=0x1000000000000063,
            char_guid=99,
            map_id=530,
            x=400.5,
            y=500.25,
            z=60.75,
            orientation=2.5,
        )
    )

    payload = build_server_built_player_create(ctx, player)
    fallback = build_server_built_player_create(ctx)

    assert payload is not None
    assert fallback is not None
    assert int.from_bytes(payload[:2], "little") == 530
    assert payload != fallback


def test_player_value_update_runtime_path_is_byte_identical():
    session = _packet_session()
    ctx = WorldLoginContext.from_session(session)
    player = Player.from_session(session)

    assert build_server_built_minimal_player_value_update(
        ctx,
        player,
    ) == build_server_built_minimal_player_value_update(ctx)


def test_player_value_update_uses_runtime_identity_map_and_scale(monkeypatch):
    ctx = WorldLoginContext.from_session(_packet_session())
    player = Player.from_session(
        _packet_session(
            world_guid=0x1000000000000063,
            char_guid=99,
            map_id=530,
        )
    )
    player.scale = 1.5
    captured = {}

    def capture_payload(**fields):
        captured.update(fields)
        return b"runtime-update"

    monkeypatch.setattr(
        "server.modules.handlers.world.bootstrap.playerobjects."
        "build_multi_u32_update_object_payload",
        capture_payload,
    )

    payload = build_server_built_minimal_player_value_update(ctx, player)

    assert payload == b"runtime-update"
    assert captured["guid"] == player.runtime_guid
    assert captured["map_id"] == player.map_id
    expected_scale = struct.unpack("<I", struct.pack("<f", 1.5))[0]
    assert dict(captured["field_updates"])[7] == expected_scale


def test_player_move_runtime_path_is_byte_identical(monkeypatch):
    monkeypatch.setattr(movement_handlers.time, "time", lambda: 1234.5)
    fallback_session = _packet_session()
    runtime_session = _packet_session()
    player = Player.from_session(runtime_session)

    assert movement_handlers.build_smsg_player_move_payload(
        runtime_session,
        player,
    ) == movement_handlers.build_smsg_player_move_payload(fallback_session)


def test_active_mover_runtime_path_is_byte_identical():
    session = _packet_session()
    ctx = WorldLoginContext.from_session(session)
    player = Player.from_session(session)

    assert build_SMSG_MOVE_SET_ACTIVE_MOVER(
        ctx,
        player,
    ) == build_SMSG_MOVE_SET_ACTIVE_MOVER(ctx)


def test_login_verify_world_runtime_path_is_byte_identical():
    session = _packet_session()
    ctx = WorldLoginContext.from_session(session)
    player = Player.from_session(session)

    assert build_SMSG_LOGIN_VERIFY_WORLD(
        ctx,
        player,
    ) == build_SMSG_LOGIN_VERIFY_WORLD(ctx)


def test_player_move_reads_position_and_orientation_from_runtime(monkeypatch):
    monkeypatch.setattr(movement_handlers.time, "time", lambda: 1234.5)
    fallback_session = _packet_session()
    runtime_session = _packet_session()
    player = Player.from_session(
        _packet_session(x=400.5, y=500.25, z=60.75, orientation=2.5)
    )

    runtime_payload = movement_handlers.build_smsg_player_move_payload(
        runtime_session,
        player,
    )
    fallback_payload = movement_handlers.build_smsg_player_move_payload(
        fallback_session,
    )

    assert runtime_payload is not None
    assert fallback_payload is not None
    assert runtime_payload != fallback_payload


def test_login_packet_call_site_reuses_store_player(monkeypatch):
    session = _packet_session()
    player = Player.from_session(session)
    store = get_player_runtime_store()
    store.clear()
    store.add(player)
    seen_players = []

    def capture_packet(_opcode, ctx):
        seen_players.append(getattr(ctx, "player_runtime", None))
        return b"packet"

    monkeypatch.setattr(login_handlers, "build_login_packet", capture_packet)
    monkeypatch.setattr(
        login_handlers,
        "build_database_gameobject_responses",
        lambda _session: [],
    )

    try:
        login_handlers.build_player_bootstrap_packets(session)
    finally:
        store.clear()

    assert seen_players
    assert all(seen is player for seen in seen_players)


def test_login_packet_fallback_uses_session_without_registration(monkeypatch):
    session = _packet_session()
    store = get_player_runtime_store()
    store.clear()
    seen_players = []

    def capture_packet(_opcode, ctx):
        seen_players.append(getattr(ctx, "player_runtime", None))
        return b"packet"

    monkeypatch.setattr(login_handlers, "build_login_packet", capture_packet)
    monkeypatch.setattr(
        login_handlers,
        "build_database_gameobject_responses",
        lambda _session: [],
    )

    login_handlers.build_player_bootstrap_packets(session)

    assert seen_players
    assert all(isinstance(seen, Player) for seen in seen_players)
    assert all(seen.character_guid == session.char_guid for seen in seen_players)
    assert store.get(session.char_guid) is None


def test_movement_packet_call_site_reuses_store_player(monkeypatch):
    session = _packet_session()
    player = Player.from_session(session)
    store = get_player_runtime_store()
    store.clear()
    store.add(player)
    captured = {}

    def capture_payload(source_session, player=None):
        captured["session"] = source_session
        captured["player"] = player
        return b"movement"

    monkeypatch.setattr(
        movement_handlers,
        "build_smsg_player_move_payload",
        capture_payload,
    )

    try:
        response = state_runtime._build_player_move_response(session)
    finally:
        store.clear()

    assert response == ("SMSG_PLAYER_MOVE", b"movement")
    assert captured == {"session": session, "player": player}
