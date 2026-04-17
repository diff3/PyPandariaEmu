import sys
import types
from types import SimpleNamespace

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


def test_refresh_region_weather_uses_snow_in_snow_zone(monkeypatch):
    _stub_login_modules()

    test_state = GlobalState()
    test_state.weather_seed = 12345
    monkeypatch.setattr(runtime, "global_state", test_state)
    monkeypatch.setattr(runtime.ConfigLoader, "load_config", staticmethod(lambda: {"worldserver": {"weather_cycle_seconds": 600}}))
    monkeypatch.setattr(runtime.time, "time", lambda: 0.0)
    region_manager.regions.clear()

    session = _make_session(name="Alice", guid=1, map_id=0, state=test_state)
    session.zone = 1
    runtime.attach_session_to_world_state(session, map_id=0)

    changed = runtime.refresh_region_weather(session)

    assert changed is False
    assert session.weather == {"weather_type": 8, "density": 0.75, "abrupt": 0}


def test_refresh_region_weather_is_per_session_zone_not_per_map(monkeypatch):
    _stub_login_modules()

    test_state = GlobalState()
    test_state.weather_seed = 12345
    monkeypatch.setattr(runtime, "global_state", test_state)
    monkeypatch.setattr(runtime.ConfigLoader, "load_config", staticmethod(lambda: {"worldserver": {"weather_cycle_seconds": 600}}))
    monkeypatch.setattr(runtime.time, "time", lambda: 0.0)
    region_manager.regions.clear()

    snow_session = _make_session(name="Snow", guid=1, map_id=0, state=test_state)
    snow_session.zone = 1
    runtime.attach_session_to_world_state(snow_session, map_id=0)

    rain_session = _make_session(name="Rain", guid=2, map_id=0, state=test_state)
    rain_session.zone = 1637
    runtime.attach_session_to_world_state(rain_session, map_id=0)

    runtime.refresh_region_weather(snow_session)
    runtime.refresh_region_weather(rain_session)

    assert snow_session.weather == {"weather_type": 8, "density": 0.75, "abrupt": 0}
    assert rain_session.weather == {"weather_type": 5, "density": 0.75, "abrupt": 0}


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
    assert other.send_response_log == [[move_response]]


def test_same_map_teleport_self_resync_includes_visible_item_update(monkeypatch):
    captured = []
    packets_module = types.ModuleType("server.modules.handlers.world.login.packets")
    packets_module.build_login_packet = lambda name, ctx: (
        captured.append((name, list(getattr(ctx, "equipment_cache_raw", []) or [])))
        or (b"0006" if name == "SMSG_UPDATE_OBJECT_1773613185_0006" else None)
    )
    sys.modules["server.modules.handlers.world.login.packets"] = packets_module

    context_module = types.ModuleType("server.modules.handlers.world.login.context")

    class _WorldLoginContext:
        @staticmethod
        def from_session(session):
            return SimpleNamespace(equipment_cache_raw=list(getattr(session, "equipment_cache_raw", []) or []))

    context_module.WorldLoginContext = _WorldLoginContext
    sys.modules["server.modules.handlers.world.login.context"] = context_module

    inventory_sync_module = types.ModuleType("server.modules.handlers.world.inventory_sync")
    inventory_sync_module.build_self_visible_item_update_responses = lambda session: [
        ("SMSG_UPDATE_OBJECT", b"visible-items")
    ]
    sys.modules["server.modules.handlers.world.inventory_sync"] = inventory_sync_module

    session = WorldSession()
    session.char_guid = 7
    session.map_id = 1
    session.is_morphed = True
    session.equipment_cache_raw = [111, 0, 222, 0]

    responses = runtime.build_same_map_teleport_self_resync_responses(session)

    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"0006"),
        ("SMSG_UPDATE_OBJECT", b"visible-items"),
    ]
    assert captured == [("SMSG_UPDATE_OBJECT_1773613185_0006", [111, 0, 222, 0])]


def test_self_player_appearance_keeps_equipment_cache_when_morphed(monkeypatch):
    captured = []
    packets_module = types.ModuleType("server.modules.handlers.world.login.packets")
    packets_module.build_login_packet = lambda name, ctx: (
        captured.append((name, list(getattr(ctx, "equipment_cache_raw", []) or [])))
        or (b"0002" if name == "SMSG_UPDATE_OBJECT_1773613176_0002" else None)
    )
    sys.modules["server.modules.handlers.world.login.packets"] = packets_module

    context_module = types.ModuleType("server.modules.handlers.world.login.context")

    class _WorldLoginContext:
        @staticmethod
        def from_session(session):
            return SimpleNamespace(equipment_cache_raw=list(getattr(session, "equipment_cache_raw", []) or []))

    context_module.WorldLoginContext = _WorldLoginContext
    sys.modules["server.modules.handlers.world.login.context"] = context_module

    inventory_sync_module = types.ModuleType("server.modules.handlers.world.inventory_sync")
    inventory_sync_module.build_self_visible_item_update_responses = lambda session: [
        ("SMSG_UPDATE_OBJECT", b"visible-items")
    ]
    sys.modules["server.modules.handlers.world.inventory_sync"] = inventory_sync_module

    session = WorldSession()
    session.char_guid = 7
    session.map_id = 1
    session.is_morphed = True
    session.equipment_cache_raw = [111, 0, 222, 0]

    responses = runtime.build_self_player_appearance_responses(session)

    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"0002"),
        ("SMSG_UPDATE_OBJECT", b"visible-items"),
    ]
    assert captured == [("SMSG_UPDATE_OBJECT_1773613176_0002", [111, 0, 222, 0])]


def test_remote_player_create_keeps_equipment_cache_when_morphed(monkeypatch):
    captured = []
    packets_module = types.ModuleType("server.modules.handlers.world.login.packets")
    packets_module.build_login_packet = lambda name, ctx: (
        captured.append((name, list(getattr(ctx, "equipment_cache_raw", []) or [])))
        or (b"0002-remote" if name == "SMSG_UPDATE_OBJECT_1773613176_0002" else None)
    )
    sys.modules["server.modules.handlers.world.login.packets"] = packets_module

    context_module = types.ModuleType("server.modules.handlers.world.login.context")

    class _WorldLoginContext:
        @staticmethod
        def from_session(session):
            return SimpleNamespace(equipment_cache_raw=list(getattr(session, "equipment_cache_raw", []) or []))

    context_module.WorldLoginContext = _WorldLoginContext
    sys.modules["server.modules.handlers.world.login.context"] = context_module

    session = WorldSession()
    session.char_guid = 7
    session.map_id = 1
    session.is_morphed = True
    session.equipment_cache_raw = [111, 0, 222, 0]

    response = runtime._build_player_create_update_response(session)

    assert response == ("SMSG_UPDATE_OBJECT", b"0002-remote")
    assert captured == [("SMSG_UPDATE_OBJECT_1773613176_0002", [111, 0, 222, 0])]
