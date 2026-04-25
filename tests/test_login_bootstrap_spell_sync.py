from __future__ import annotations

import sys
from types import SimpleNamespace
import types

database_module = types.ModuleType("server.modules.database.DatabaseConnection")
database_module.DatabaseConnection = type("DatabaseConnection", (), {})
sys.modules.setdefault("server.modules.database.DatabaseConnection", database_module)

inventory_module = types.ModuleType("server.modules.game.inventory")
inventory_module.refresh_session_inventory = lambda session: None
inventory_module.persist_session_inventory = lambda session, **kwargs: None
sys.modules.setdefault("server.modules.game.inventory", inventory_module)

characters_module = types.ModuleType("server.modules.handlers.world.characters.characters")
characters_module.handle_CMSG_CHAR_CREATE = lambda *args, **kwargs: (0, None)
characters_module.handle_CMSG_CHAR_DELETE = lambda *args, **kwargs: (0, None)
characters_module.handle_CMSG_REORDER_CHARACTERS = lambda *args, **kwargs: (0, None)
sys.modules.setdefault("server.modules.handlers.world.characters.characters", characters_module)

from server.modules.handlers.world.opcodes import login as login_handlers
from server.session.world_session import LoginState


def test_run_replay_bootstrap_flag_on_uses_replay(monkeypatch) -> None:
    session = SimpleNamespace()

    monkeypatch.setattr(login_handlers, "USE_REPLAY_BOOTSTRAP", True)
    monkeypatch.setattr(
        login_handlers.bootstrap_replay,
        "replay_movement_focus_sequence",
        lambda _session: [("SMSG_UPDATE_OBJECT", b"create")],
    )

    assert login_handlers.run_replay_bootstrap(session) == [("SMSG_UPDATE_OBJECT", b"create")]


def test_run_replay_bootstrap_flag_off_uses_future_server_path(monkeypatch) -> None:
    session = SimpleNamespace()

    monkeypatch.setattr(login_handlers, "USE_REPLAY_BOOTSTRAP", False)
    monkeypatch.setattr(
        login_handlers.bootstrap_replay,
        "replay_movement_focus_sequence",
        lambda _session: [("SMSG_UPDATE_OBJECT", b"create")],
    )

    assert login_handlers.run_replay_bootstrap(session) == []


def test_world_bootstrap_sends_known_spells_after_update_object(monkeypatch) -> None:
    """Queue a post-create spell sync so known spells land after player create."""
    session = SimpleNamespace(
        post_loading_sent=False,
        player_object_sent=False,
        loading_screen_done=False,
        login_state=LoginState.PLAYER_LOGIN,
    )
    ctx = SimpleNamespace()
    state_changes: list[LoginState] = []

    monkeypatch.setattr(
        login_handlers,
        "_set_login_state",
        lambda _session, state: state_changes.append(state),
    )
    monkeypatch.setattr(
        login_handlers,
        "build_pre_update_object_packets",
        lambda _ctx: [("PRE", b"pre")],
    )
    monkeypatch.setattr(
        login_handlers,
        "run_replay_bootstrap",
        lambda _session: [("SMSG_UPDATE_OBJECT", b"create")],
    )
    monkeypatch.setattr(
        login_handlers.spells_handlers,
        "build_active_mover_spell_sync_responses",
        lambda _session: [("SMSG_SEND_KNOWN_SPELLS", b"known-spells")],
    )
    monkeypatch.setattr(
        login_handlers,
        "build_login_inventory_sync_responses",
        lambda _session: [],
    )
    monkeypatch.setattr(
        login_handlers,
        "trigger_inventory_activation",
        lambda _session: [],
    )
    monkeypatch.setattr(
        login_handlers,
        "build_explored_zones_update_response",
        lambda _session: None,
    )
    monkeypatch.setattr(
        login_handlers,
        "build_post_update_object_packets",
        lambda _ctx: [],
    )
    monkeypatch.setattr(
        login_handlers,
        "build_world_bootstrap_packets",
        lambda _ctx: [
            ("SMSG_MOVE_SET_ACTIVE_MOVER", b"active-mover"),
            ("BOOT", b"boot"),
        ],
    )

    responses = login_handlers._queue_world_bootstrap_transition(session, ctx)

    assert state_changes == [LoginState.WORLD_BOOTSTRAP]
    assert responses == [
        ("PRE", b"pre"),
        ("SMSG_UPDATE_OBJECT", b"create"),
        ("SMSG_SEND_KNOWN_SPELLS", b"known-spells"),
        ("BOOT", b"boot"),
    ]
    assert session.loading_screen_done is True
    assert session.post_loading_sent is True


def test_world_bootstrap_refreshes_weather_before_weather_packet(monkeypatch) -> None:
    """Use current session weather when the initial SMSG_WEATHER is built."""
    session = SimpleNamespace(
        post_loading_sent=False,
        player_object_sent=True,
        loading_screen_done=False,
        login_state=LoginState.PLAYER_LOGIN,
        weather={"weather_type": 0, "density": 0.0, "abrupt": 0},
    )
    ctx = SimpleNamespace(weather={})
    captured_weather = {}

    monkeypatch.setattr(login_handlers, "_set_login_state", lambda _session, _state: None)
    monkeypatch.setattr(login_handlers, "build_pre_update_object_packets", lambda _ctx: [])
    monkeypatch.setattr(login_handlers, "build_post_update_object_packets", lambda _ctx: [])
    monkeypatch.setattr(
        login_handlers,
        "refresh_region_weather",
        lambda current_session: setattr(
            current_session,
            "weather",
            {"weather_type": 5, "density": 0.75, "abrupt": 0},
        ),
    )
    monkeypatch.setattr(
        login_handlers.spells_handlers,
        "build_active_mover_spell_sync_responses",
        lambda _session: [],
    )
    monkeypatch.setattr(login_handlers, "build_login_inventory_sync_responses", lambda _session: [])
    monkeypatch.setattr(login_handlers, "trigger_inventory_activation", lambda _session: [])
    monkeypatch.setattr(login_handlers, "build_explored_zones_update_response", lambda _session: None)

    def build_bootstrap(current_ctx):
        captured_weather.update(current_ctx.weather)
        return [("SMSG_WEATHER", b"weather")]

    monkeypatch.setattr(login_handlers, "build_world_bootstrap_packets", build_bootstrap)

    responses = login_handlers._queue_world_bootstrap_transition(session, ctx)

    assert captured_weather == {"weather_type": 5, "density": 0.75, "abrupt": 0}
    assert ctx.weather == {"weather_type": 5, "density": 0.75, "abrupt": 0}
    assert responses == [("SMSG_WEATHER", b"weather")]


def test_teleport_bootstrap_sends_known_spells_after_update_object(monkeypatch) -> None:
    """Queue a post-teleport spell sync so language/mount state survives world transfers."""
    session = SimpleNamespace(
        loading_screen_done=False,
        post_loading_sent=False,
        teleport_pending=True,
        worldport_ack_pending=True,
        teleport_destination="test",
    )
    ctx = SimpleNamespace()
    state_changes: list[LoginState] = []

    monkeypatch.setattr(
        login_handlers,
        "_set_login_state",
        lambda _session, state: state_changes.append(state),
    )
    monkeypatch.setattr(
        login_handlers,
        "build_login_packet",
        lambda opcode_name, _ctx: {
            "SMSG_LOGIN_VERIFY_WORLD": b"verify",
            "SMSG_LOGIN_SET_TIME_SPEED": b"time",
            "SMSG_BIND_POINT_UPDATE": b"bind",
            "SMSG_TIME_SYNC_REQUEST": b"sync",
            "SMSG_PHASE_SHIFT_CHANGE": b"phase",
            "SMSG_INIT_WORLD_STATES": b"states",
            "SMSG_WEATHER": b"weather",
            "SMSG_QUERY_TIME_RESPONSE": b"query-time",
        }.get(opcode_name),
    )
    monkeypatch.setattr(
        login_handlers,
        "run_replay_bootstrap",
        lambda _session: [("SMSG_UPDATE_OBJECT", b"create")],
    )
    monkeypatch.setattr(
        login_handlers.spells_handlers,
        "build_active_mover_spell_sync_responses",
        lambda _session: [("SMSG_SEND_KNOWN_SPELLS", b"known-spells")],
    )
    monkeypatch.setattr(
        login_handlers,
        "build_login_inventory_sync_responses",
        lambda _session: [],
    )
    monkeypatch.setattr(
        login_handlers,
        "trigger_inventory_activation",
        lambda _session: [],
    )
    monkeypatch.setattr(
        login_handlers,
        "build_explored_zones_update_response",
        lambda _session: None,
    )

    responses = login_handlers._queue_teleport_world_transition(session, ctx)

    assert state_changes == [LoginState.WORLD_BOOTSTRAP]
    assert ("SMSG_UPDATE_OBJECT", b"create") in responses
    assert ("SMSG_SEND_KNOWN_SPELLS", b"known-spells") in responses
    assert responses.index(("SMSG_SEND_KNOWN_SPELLS", b"known-spells")) > responses.index(
        ("SMSG_UPDATE_OBJECT", b"create")
    )
    assert session.loading_screen_done is True
    assert session.post_loading_sent is True
    assert session.teleport_pending is False
    assert session.worldport_ack_pending is False
    assert session.teleport_destination is None
