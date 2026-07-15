import sys
import types
from types import SimpleNamespace


def _install_lifecycle_test_stubs():
    encoder_module = types.ModuleType("DSL.modules.EncoderHandler")
    encoder_module.EncoderHandler = type("EncoderHandler", (), {})
    sys.modules["DSL.modules.EncoderHandler"] = encoder_module

    characters_module = types.ModuleType("server.modules.handlers.world.characters.characters")
    characters_module.preload_cache = lambda: None
    sys.modules["server.modules.handlers.world.characters.characters"] = characters_module

    inventory_module = types.ModuleType("server.modules.game.inventory")
    inventory_module.persist_session_inventory = lambda session: True
    sys.modules["server.modules.game.inventory"] = inventory_module

    session_runtime_module = types.ModuleType("server.session.runtime")
    session_runtime_module.session = SimpleNamespace()
    sys.modules["server.session.runtime"] = session_runtime_module

    login_module = types.ModuleType("server.modules.handlers.world.opcodes.login")
    login_module._reset_login_flow_state = lambda session: None
    sys.modules["server.modules.handlers.world.opcodes.login"] = login_module

    movement_module = types.ModuleType("server.modules.handlers.world.opcodes.movement")
    movement_module._save_current_position_like_command = lambda *args, **kwargs: True
    sys.modules["server.modules.handlers.world.opcodes.movement"] = movement_module

    global_state_module = types.ModuleType("server.modules.handlers.world.state.global_state")
    global_state_module.global_state = SimpleNamespace(chat_channels={}, sessions=set())
    sys.modules["server.modules.handlers.world.state.global_state"] = global_state_module

    runtime_module = types.ModuleType("server.modules.handlers.world.state.runtime")
    runtime_module.broadcast_player_remove = lambda session: None
    sys.modules["server.modules.handlers.world.state.runtime"] = runtime_module


def test_handle_disconnect_session_persists_inventory(monkeypatch):
    _install_lifecycle_test_stubs()
    sys.modules.pop("server.modules.handlers.world.runtime.lifecycle", None)
    from server.modules.handlers.world.runtime import lifecycle

    calls = []
    monkeypatch.setattr(lifecycle, "broadcast_player_remove", lambda session: calls.append(("remove", session)))
    monkeypatch.setattr(
        lifecycle,
        "save_current_position_like_command",
        lambda session, **kwargs: calls.append(("position", kwargs)) or True,
    )
    monkeypatch.setattr(
        lifecycle,
        "persist_session_inventory",
        lambda session: calls.append(("inventory", session)) or True,
    )
    monkeypatch.setattr(
        lifecycle.login_handlers,
        "_reset_login_flow_state",
        lambda session: calls.append(("reset", session)),
    )

    class _Session:
        __hash__ = object.__hash__

    state = SimpleNamespace(chat_channels={"world": set()}, sessions=set())
    region = SimpleNamespace(players=set())
    session = _Session()
    session._disconnect_handled = False
    session.char_guid = 42
    session.global_state = state
    session.region = region
    session.send_response = lambda responses: None
    session.visible_guids = {1, 2}
    session.near_teleport_pending = True
    session.worldport_ack_pending = True
    state.chat_channels["world"].add(session)
    state.sessions.add(session)
    region.players.add(session)

    from server.modules.handlers.world.runtime.player import Player
    from server.modules.handlers.world.runtime.player_store import (
        get_player_runtime_store,
    )

    player_store = get_player_runtime_store()
    player_store.clear()
    player_store.add(Player.from_session(session))

    lifecycle.handle_disconnect_session(session)

    assert ("inventory", session) in calls
    assert ("remove", session) in calls
    assert ("reset", session) in calls
    assert session.region is None
    assert session.send_response is None
    assert session.visible_guids == set()
    assert session.near_teleport_pending is False
    assert session.worldport_ack_pending is False
    assert session not in state.sessions
    assert session not in state.chat_channels["world"]
    assert session not in region.players
    assert player_store.get(42) is None


def test_handle_disconnect_session_finalizes_taxi_before_position_save(monkeypatch):
    _install_lifecycle_test_stubs()
    taxi_module = types.ModuleType("server.modules.handlers.world.taxi_runtime")
    sys.modules["server.modules.handlers.world.taxi_runtime"] = taxi_module
    sys.modules.pop("server.modules.handlers.world.runtime.lifecycle", None)
    from server.modules.handlers.world.runtime import lifecycle

    calls = []

    def _complete_taxi_for_disconnect(session):
        calls.append(("taxi", session.x, session.y, session.z))
        session.x = 50.0
        session.y = 60.0
        session.z = 7.0
        session.taxi_state = None
        session.taxi_controls_locked = False
        session.player_travel_state = "NORMAL"
        return True

    taxi_module.complete_taxi_for_disconnect = _complete_taxi_for_disconnect
    monkeypatch.setattr(lifecycle, "broadcast_player_remove", lambda session: calls.append(("remove", session.x, session.y, session.z)))
    monkeypatch.setattr(
        lifecycle,
        "save_current_position_like_command",
        lambda session, **kwargs: calls.append(("position", session.x, session.y, session.z, kwargs)) or True,
    )
    monkeypatch.setattr(lifecycle, "persist_session_inventory", lambda session: calls.append(("inventory", session)) or True)
    monkeypatch.setattr(lifecycle.login_handlers, "_reset_login_flow_state", lambda session: None)

    session = SimpleNamespace(
        _disconnect_handled=False,
        char_guid=42,
        global_state=SimpleNamespace(chat_channels={"world": set()}, sessions=set()),
        region=None,
        send_response=lambda responses: None,
        visible_guids=set(),
        near_teleport_pending=False,
        worldport_ack_pending=False,
        x=0.0,
        y=0.0,
        z=0.0,
        taxi_state=object(),
        taxi_controls_locked=True,
        player_travel_state="TAXI_FLIGHT",
    )

    lifecycle.handle_disconnect_session(session)

    assert calls[0] == ("taxi", 0.0, 0.0, 0.0)
    assert calls[1] == ("remove", 50.0, 60.0, 7.0)
    assert calls[2][0:4] == ("position", 50.0, 60.0, 7.0)
    assert calls[2][4]["reason"] == "disconnect"
    assert calls[2][4]["online"] == 0
    assert session.taxi_state is None
    assert session.taxi_controls_locked is False
    assert session.player_travel_state == "NORMAL"

