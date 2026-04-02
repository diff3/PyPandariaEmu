import sys
import types

from server.modules.handlers.world.state.global_state import GlobalState
from server.modules.handlers.world.state.region_manager import region_manager
from server.modules.handlers.world.state import runtime
from server.session.world_session import WorldSession


def _stub_login_modules():
    packets_module = types.ModuleType("server.modules.handlers.world.login.packets")
    packets_module.build_login_packet = lambda name, ctx: f"{name}|{getattr(ctx, 'game_time', 0)}".encode()
    sys.modules["server.modules.handlers.world.login.packets"] = packets_module

    login_module = types.ModuleType("server.modules.handlers.world.opcodes.login")
    login_module._build_world_login_context = lambda session: session
    sys.modules["server.modules.handlers.world.opcodes.login"] = login_module


def _make_session(*, name: str, guid: int, map_id: int, state: GlobalState) -> WorldSession:
    session = WorldSession()
    session.player_name = name
    session.char_guid = guid
    session.map_id = map_id
    session.visible_guids = set()
    session.send_response_log = []
    session.send_response = lambda responses, target=session: target.send_response_log.append(list(responses))
    session.global_state = state
    return session


def test_world_time_persists_for_new_sessions_until_restart(monkeypatch):
    _stub_login_modules()

    test_state = GlobalState()
    monkeypatch.setattr(runtime, "global_state", test_state)
    region_manager.regions.clear()

    existing = _make_session(name="Alice", guid=1, map_id=1, state=test_state)
    test_state.chat_channels.setdefault("world", set()).add(existing)
    test_state.sessions.add(existing)

    runtime.broadcast_world_time(12, 34)

    assert int(existing.time_offset) == int(test_state.time_offset)
    assert existing.send_response_log[-1][0][0] == "SMSG_LOGIN_SET_TIME_SPEED"

    newcomer = _make_session(name="Bob", guid=2, map_id=1, state=test_state)
    runtime.attach_session_to_world_state(newcomer, map_id=1)

    assert int(newcomer.time_offset) == int(test_state.time_offset)
    assert float(newcomer.time_speed) == float(test_state.time_speed)


def test_manual_weather_persists_per_map_for_new_sessions_until_restart(monkeypatch):
    _stub_login_modules()

    test_state = GlobalState()
    monkeypatch.setattr(runtime, "global_state", test_state)
    region_manager.regions.clear()

    source = _make_session(name="Alice", guid=1, map_id=1, state=test_state)
    runtime.attach_session_to_world_state(source, map_id=1)

    runtime.broadcast_region_weather(source, 5, 0.8, 1)

    expected = {"weather_type": 5, "density": 0.8, "abrupt": 1}
    assert test_state.manual_region_weather[1] == expected

    newcomer_same_map = _make_session(name="Bob", guid=2, map_id=1, state=test_state)
    runtime.attach_session_to_world_state(newcomer_same_map, map_id=1)

    assert newcomer_same_map.weather == expected
    assert region_manager.get_region(1).weather_manual is True


def test_visible_peer_gets_value_updates_instead_of_remove_create(monkeypatch):
    _stub_login_modules()

    source = _make_session(name="Roges", guid=8, map_id=1, state=GlobalState())
    other = _make_session(name="Selene", guid=13, map_id=1, state=GlobalState())
    source.login_state = "IN_WORLD"
    other.login_state = "IN_WORLD"
    source.x = source.y = source.z = 0.0
    other.x = other.y = other.z = 0.0
    source.instance_id = other.instance_id = 0
    source.phase_mask = other.phase_mask = 1
    source.visible_guids.add(other.char_guid)
    other.visible_guids.add(source.char_guid)

    monkeypatch.setattr(runtime, "_sessions_in_visibility_range", lambda left, right: True)

    move_response = ("SMSG_PLAYER_MOVE", b"move")
    value_responses = [
        ("SMSG_UPDATE_OBJECT", b"0004"),
        ("SMSG_UPDATE_OBJECT", b"0006"),
    ]
    changed_for_source, changed_for_other, updated_for_other = runtime._reconcile_session_visibility_pair(
        source,
        other,
        source_move_response=move_response,
        source_value_responses=value_responses,
    )

    assert changed_for_source is False
    assert changed_for_other is False
    assert updated_for_other is True
    assert other.send_response_log == [[move_response, *value_responses]]
