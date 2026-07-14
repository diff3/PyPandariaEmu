import sys
import types
from types import SimpleNamespace

from server.modules.handlers.world.state.global_state import GlobalState
from server.modules.handlers.world.state.region_manager import region_manager
from server.modules.handlers.world.state import runtime
from server.modules.handlers.world.state import weather_zone_registry
from server.modules.handlers.world.state.weather_zone_registry import AreaTableEntry, WeatherZoneEntry
from server.modules.handlers.world.runtime import Player, get_player_runtime_store
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


def test_manual_weather_persists_per_zone_for_new_sessions_until_restart(monkeypatch):
    _stub_login_modules()

    test_state = GlobalState()
    monkeypatch.setattr(runtime, "global_state", test_state)
    region_manager.regions.clear()

    source = _make_session(name="Alice", guid=1, map_id=1, state=test_state)
    source.zone = 1637
    runtime.attach_session_to_world_state(source, map_id=1)
    source.zone = 1637

    runtime.broadcast_region_weather(source, 5, 0.8, 1)

    expected = {"weather_type": 5, "density": 0.8, "abrupt": 1}
    assert test_state.manual_region_weather[1637] == expected

    newcomer_same_zone = _make_session(name="Bob", guid=2, map_id=1, state=test_state)
    newcomer_same_zone.zone = 1637
    runtime.attach_session_to_world_state(newcomer_same_zone, map_id=1)
    newcomer_same_zone.zone = 1637
    runtime.refresh_region_weather(newcomer_same_zone)

    newcomer_other_zone = _make_session(name="Clara", guid=3, map_id=1, state=test_state)
    newcomer_other_zone.zone = 1
    runtime.attach_session_to_world_state(newcomer_other_zone, map_id=1)
    newcomer_other_zone.zone = 1
    runtime.refresh_region_weather(newcomer_other_zone)

    assert newcomer_same_zone.weather == expected
    assert newcomer_other_zone.weather != expected
    assert region_manager.get_region(1).weather_manual is True


def test_admin_weather_override_command_updates_runtime_state(monkeypatch):
    test_state = GlobalState()
    monkeypatch.setattr(runtime, "global_state", test_state)

    runtime._apply_weather_runtime_command({
        "action": "override",
        "zone": 1637,
        "weather": "heavy_rain",
        "density": 0.8,
    })

    assert test_state.manual_region_weather[1637] == {
        "weather_type": 5,
        "density": 0.8,
        "abrupt": 1,
    }


def test_admin_weather_chance_command_updates_runtime_cache(monkeypatch):
    cached_rows = [{"zone": 148, "spring_rain_chance": 10}]
    monkeypatch.setattr(runtime._configured_weather_rows, "_rows", cached_rows, raising=False)

    runtime._apply_weather_runtime_command({
        "action": "chance",
        "zone": 148,
        "kind": "rain",
        "season": "spring",
        "value": 80,
    })

    assert cached_rows[0]["spring_rain_chance"] == 80


def test_weather_zone_registry_collapses_child_zones_without_explicit_weather(monkeypatch):
    monkeypatch.setattr(weather_zone_registry.area_table_entries, "_cache", {
        12: AreaTableEntry(12, 0, 0, "Elwynn Forest"),
        87: AreaTableEntry(87, 12, 0, "Goldshire"),
        40: AreaTableEntry(40, 0, 0, "Westfall"),
    }, raising=False)

    registry = weather_zone_registry.canonical_weather_zone_registry(set())

    assert 12 in registry
    assert 87 not in registry
    assert "Goldshire" in registry[12].aliases


def test_weather_zone_registry_keeps_explicit_child_weather(monkeypatch):
    monkeypatch.setattr(weather_zone_registry.area_table_entries, "_cache", {
        12: AreaTableEntry(12, 0, 0, "Elwynn Forest"),
        87: AreaTableEntry(87, 12, 0, "Goldshire"),
    }, raising=False)

    registry = weather_zone_registry.canonical_weather_zone_registry({87})

    assert 12 in registry
    assert 87 in registry
    assert registry[87].explicit_weather is True
    assert "Goldshire" not in registry[12].aliases


def test_weather_snapshot_uses_canonical_registry_not_only_game_weather(monkeypatch):
    test_state = GlobalState()
    monkeypatch.setattr(runtime, "global_state", test_state)
    monkeypatch.setattr(runtime, "_process_weather_runtime_commands", lambda: None)
    monkeypatch.setattr(runtime, "_current_weather_season", lambda: "spring")
    monkeypatch.setattr(runtime, "_weather_cycle_seconds", lambda: 600)
    monkeypatch.setattr(runtime, "_weather_cycle_slot", lambda now=None: 0)
    monkeypatch.setattr(runtime, "_configured_weather_rows", lambda: [{
        "zone": 148,
        "spring_rain_chance": 15,
        "spring_snow_chance": 0,
        "spring_storm_chance": 20,
    }])
    monkeypatch.setattr(runtime, "canonical_weather_zone_registry", lambda explicit: {
        148: WeatherZoneEntry(148, 0, 0, "Darkshore", "darkshore", ("Auberdine",), (465,)),
        440: WeatherZoneEntry(440, 0, 1, "Tanaris", "tanaris", (), ()),
    })

    rows = runtime.weather_runtime_snapshot_rows()
    names = {row["canonical_name"]: row for row in rows}

    assert set(names) == {"Darkshore", "Tanaris"}
    assert names["Darkshore"]["rain_chance"] == 15
    assert names["Tanaris"]["rain_chance"] == 0
    assert names["Darkshore"]["search_aliases"] == ["Auberdine"]


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
    monkeypatch.setitem(sys.modules, "server.modules.handlers.world.inventory_sync", inventory_sync_module)

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


def test_same_map_teleport_world_object_resync_streams_immediately(monkeypatch):
    calls = []
    movement_module = types.ModuleType("server.modules.handlers.world.opcodes.movement")

    def _fake_stream(session):
        calls.append(
            (
                session,
                float(getattr(session, "last_gameobject_stream_at", -1.0)),
                float(getattr(session, "last_npc_stream_at", -1.0)),
            )
        )
        return [("SMSG_UPDATE_OBJECT", b"world-objects")]

    movement_module._maybe_stream_world_objects = _fake_stream
    monkeypatch.setitem(sys.modules, "server.modules.handlers.world.opcodes.movement", movement_module)

    session = WorldSession()
    session.char_guid = 7
    session.map_id = 1
    session.gameobjects_visible = True
    session.npc_auto_stream = True
    session.last_gameobject_stream_at = 123.0
    session.last_npc_stream_at = 456.0

    responses = runtime.build_same_map_teleport_world_object_resync_responses(session)

    assert responses == [("SMSG_UPDATE_OBJECT", b"world-objects")]
    assert calls == [(session, 0.0, 0.0)]


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
    monkeypatch.setitem(sys.modules, "server.modules.handlers.world.inventory_sync", inventory_sync_module)

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


def test_send_player_create_appends_remote_visible_item_updates(monkeypatch):
    observer = _make_session(name="Observer", guid=1, map_id=1, state=GlobalState())
    source = _make_session(name="Source", guid=7, map_id=1, state=GlobalState())
    observer.login_state = "IN_WORLD"
    source.login_state = "IN_WORLD"

    monkeypatch.setattr(
        runtime,
        "_build_player_create_responses",
        lambda session: [("SMSG_UPDATE_OBJECT", b"0002-remote")] if session is source else [],
    )

    inventory_sync_module = types.ModuleType("server.modules.handlers.world.inventory_sync")
    captured_sessions = []
    inventory_sync_module.build_self_visible_item_update_responses = lambda session: (
        captured_sessions.append(session)
        or [("SMSG_UPDATE_OBJECT", b"visible-items-1"), ("SMSG_UPDATE_OBJECT", b"visible-items-2")]
    )
    monkeypatch.setitem(sys.modules, "server.modules.handlers.world.inventory_sync", inventory_sync_module)

    sent = runtime._send_player_create(observer, source)

    assert sent is True
    assert captured_sessions == [source]
    assert observer.send_response_log == [[
        ("SMSG_UPDATE_OBJECT", b"0002-remote"),
        ("SMSG_UPDATE_OBJECT", b"visible-items-1"),
        ("SMSG_UPDATE_OBJECT", b"visible-items-2"),
    ]]
    assert source.char_guid in observer.visible_guids


def test_force_bilateral_visibility_resync_recreates_both_directions(monkeypatch):
    target = _make_session(name="Target", guid=7, map_id=1, state=GlobalState())
    peer = _make_session(name="Peer", guid=8, map_id=1, state=GlobalState())
    target.login_state = "IN_WORLD"
    peer.login_state = "IN_WORLD"
    target.visible_guids.add(peer.char_guid)

    monkeypatch.setattr(runtime, "iter_in_world_sessions", lambda map_id=None: [target, peer])
    monkeypatch.setattr(
        runtime,
        "_build_player_remove_update_response",
        lambda session, **kwargs: ("SMSG_UPDATE_OBJECT", f"remove:{session.char_guid}".encode("ascii")),
    )
    monkeypatch.setattr(runtime, "_build_player_create_responses", lambda session: [
        ("SMSG_UPDATE_OBJECT", f"create:{session.char_guid}".encode("ascii"))
    ])

    inventory_sync_module = types.ModuleType("server.modules.handlers.world.inventory_sync")
    inventory_sync_module.build_self_visible_item_update_responses = lambda session: [
        ("SMSG_UPDATE_OBJECT", f"visible:{session.char_guid}".encode("ascii"))
    ]
    monkeypatch.setitem(sys.modules, "server.modules.handlers.world.inventory_sync", inventory_sync_module)

    runtime.force_bilateral_visibility_resync(target, reason="test")

    assert peer.char_guid in target.visible_guids
    assert target.char_guid in peer.visible_guids
    assert target.send_response_log == [
        [("SMSG_UPDATE_OBJECT", b"remove:8")],
        [
            ("SMSG_UPDATE_OBJECT", b"create:8"),
            ("SMSG_UPDATE_OBJECT", b"visible:8"),
        ],
    ]
    assert peer.send_response_log == [[
        ("SMSG_UPDATE_OBJECT", b"create:7"),
        ("SMSG_UPDATE_OBJECT", b"visible:7"),
    ]]


def test_force_player_visibility_destroy_sends_old_observer_destroy(monkeypatch):
    state = GlobalState()
    target = _make_session(name="Target", guid=7, map_id=1, state=state)
    peer = _make_session(name="Peer", guid=8, map_id=1, state=state)
    hidden = _make_session(name="Hidden", guid=9, map_id=1, state=state)
    target.visible_guids.add(peer.char_guid)
    peer.visible_guids.add(target.char_guid)

    monkeypatch.setattr(runtime, "iter_in_world_sessions", lambda map_id=None: [target, peer, hidden])
    monkeypatch.setattr(
        runtime,
        "_build_player_remove_update_response",
        lambda session, **kwargs: (
            "SMSG_UPDATE_OBJECT",
            f"remove:{session.char_guid}:map={kwargs.get('map_id')}".encode("ascii"),
        ),
    )

    runtime.force_player_visibility_destroy(target, reason="teleport-start", map_id=1)

    assert target.visible_guids == set()
    assert target.char_guid not in peer.visible_guids
    assert target.char_guid not in hidden.visible_guids
    assert peer.send_response_log == [[("SMSG_UPDATE_OBJECT", b"remove:7:map=1")]]
    assert hidden.send_response_log == []


def test_broadcast_visible_equipment_update_sends_zero_slots_to_visible_peers(monkeypatch):
    source = _make_session(name="Source", guid=7, map_id=1, state=GlobalState())
    peer = _make_session(name="Peer", guid=8, map_id=1, state=GlobalState())
    hidden = _make_session(name="Hidden", guid=9, map_id=1, state=GlobalState())
    source.login_state = "IN_WORLD"
    peer.login_state = "IN_WORLD"
    hidden.login_state = "IN_WORLD"
    peer.visible_guids.add(source.char_guid)
    source.inventory_state = SimpleNamespace(get=lambda bag, slot: None)
    source.equipment_cache_raw = [1234] * 46

    captured = []
    inventory_sync_module = types.ModuleType("server.modules.handlers.world.inventory_sync")
    inventory_sync_module.build_self_visible_item_update_responses = lambda session: (
        captured.append(session) or [("SMSG_UPDATE_OBJECT", b"zero-visible")]
    )
    monkeypatch.setitem(sys.modules, "server.modules.handlers.world.inventory_sync", inventory_sync_module)

    runtime.global_state.sessions.clear()
    runtime.global_state.sessions.update({source, peer, hidden})

    runtime.broadcast_visible_equipment_update(source)

    assert captured == [source]
    assert peer.send_response_log == [[("SMSG_UPDATE_OBJECT", b"zero-visible")]]
    assert hidden.send_response_log == []


def test_resync_player_appearance_appends_remote_visible_item_updates(monkeypatch):
    source = _make_session(name="Source", guid=7, map_id=1, state=GlobalState())
    peer = _make_session(name="Peer", guid=8, map_id=1, state=GlobalState())
    source.login_state = "IN_WORLD"
    peer.login_state = "IN_WORLD"
    peer.visible_guids.add(source.char_guid)

    monkeypatch.setattr(runtime, "_build_player_remove_update_response", lambda session: ("SMSG_UPDATE_OBJECT", b"remove"))
    monkeypatch.setattr(runtime, "_build_player_create_update_response", lambda session: ("SMSG_UPDATE_OBJECT", b"create"))
    monkeypatch.setattr(runtime, "iter_in_world_sessions", lambda map_id=None: [source, peer])

    inventory_sync_module = types.ModuleType("server.modules.handlers.world.inventory_sync")
    inventory_sync_module.build_self_visible_item_update_responses = lambda session: [
        ("SMSG_UPDATE_OBJECT", b"visible-items")
    ]
    monkeypatch.setitem(sys.modules, "server.modules.handlers.world.inventory_sync", inventory_sync_module)

    runtime.resync_player_appearance(source)

    assert peer.send_response_log == [[
        ("SMSG_UPDATE_OBJECT", b"remove"),
        ("SMSG_UPDATE_OBJECT", b"create"),
        ("SMSG_UPDATE_OBJECT", b"visible-items"),
    ]]


def test_visibility_decision_is_identical_with_matching_runtime_players():
    store = get_player_runtime_store()
    store.clear()
    left = _make_session(name="Left", guid=101, map_id=1, state=GlobalState())
    right = _make_session(name="Right", guid=102, map_id=1, state=GlobalState())
    left.instance_id = right.instance_id = 7
    left.phase_mask = right.phase_mask = 1
    left.x, left.y, left.z = (10.0, 20.0, 30.0)
    right.x, right.y, right.z = (15.0, 25.0, 35.0)

    fallback_decision = runtime._sessions_in_visibility_range(left, right)
    store.add(Player.from_session(left))
    store.add(Player.from_session(right))
    try:
        runtime_decision = runtime._sessions_in_visibility_range(left, right)
    finally:
        store.clear()

    assert fallback_decision is True
    assert runtime_decision is fallback_decision


def test_visibility_reads_map_instance_and_position_from_runtime_player():
    store = get_player_runtime_store()
    store.clear()
    left = _make_session(name="Left", guid=201, map_id=1, state=GlobalState())
    right = _make_session(name="Right", guid=202, map_id=1, state=GlobalState())
    left.instance_id = right.instance_id = 7
    left.phase_mask = right.phase_mask = 1
    left.x, left.y, left.z = (0.0, 0.0, 0.0)
    right.x, right.y, right.z = (1.0, 1.0, 1.0)
    left_player = Player.from_session(left)
    right_player = Player.from_session(right)
    store.add(left_player)
    store.add(right_player)

    left.map_id = 530
    left.instance_id = 99
    left.x, left.y, left.z = (1000.0, 1000.0, 1000.0)

    try:
        assert runtime._sessions_in_visibility_range(left, right) is True

        left_player.map_id = 530
        assert runtime._sessions_in_visibility_range(left, right) is False

        left_player.map_id = right_player.map_id
        left_player.instance_id = 99
        assert runtime._sessions_in_visibility_range(left, right) is False

        left_player.instance_id = right_player.instance_id
        left_player.x = 1000.0
        assert runtime._sessions_in_visibility_range(left, right) is False
    finally:
        store.clear()


def test_visibility_candidate_discovery_reads_map_from_runtime_player():
    store = get_player_runtime_store()
    store.clear()
    state = GlobalState()
    session = _make_session(name="Candidate", guid=251, map_id=1, state=state)
    session.login_state = "IN_WORLD"
    state.sessions.add(session)
    player = Player.from_session(session)
    store.add(player)
    session.map_id = 530

    try:
        assert runtime.iter_in_world_sessions(state=state, map_id=1) == [session]
        assert runtime.iter_in_world_sessions(state=state, map_id=530) == []
    finally:
        store.clear()


def test_visibility_create_and_destroy_order_is_unchanged(monkeypatch):
    source = _make_session(name="Source", guid=301, map_id=1, state=GlobalState())
    other = _make_session(name="Other", guid=302, map_id=1, state=GlobalState())
    source.login_state = "IN_WORLD"
    other.login_state = "IN_WORLD"
    calls = []

    monkeypatch.setattr(
        runtime,
        "_send_player_create",
        lambda observer, visible: calls.append(
            ("create", observer.char_guid, visible.char_guid)
        ) or True,
    )
    monkeypatch.setattr(
        runtime,
        "_send_player_remove",
        lambda observer, visible: calls.append(
            ("destroy", observer.char_guid, visible.char_guid)
        ) or True,
    )
    monkeypatch.setattr(
        runtime,
        "_sessions_in_visibility_range",
        lambda left, right: True,
    )

    runtime._reconcile_session_visibility_pair(source, other)

    assert calls == [
        ("create", source.char_guid, other.char_guid),
        ("create", other.char_guid, source.char_guid),
    ]

    calls.clear()
    monkeypatch.setattr(
        runtime,
        "_sessions_in_visibility_range",
        lambda left, right: False,
    )

    runtime._reconcile_session_visibility_pair(source, other)

    assert calls == [
        ("destroy", source.char_guid, other.char_guid),
        ("destroy", other.char_guid, source.char_guid),
    ]


def test_visibility_create_context_uses_stored_player_runtime(monkeypatch):
    store = get_player_runtime_store()
    store.clear()
    source = _make_session(name="Source", guid=401, map_id=1, state=GlobalState())
    source.world_guid = 0x1000000000000191
    player = Player.from_session(source)
    store.add(player)
    captured = {}

    context_module = types.ModuleType(
        "server.modules.handlers.world.login.context",
    )

    class _WorldLoginContext:
        @staticmethod
        def from_session(_session):
            return SimpleNamespace()

    context_module.WorldLoginContext = _WorldLoginContext
    monkeypatch.setitem(
        sys.modules,
        "server.modules.handlers.world.login.context",
        context_module,
    )

    packets_module = types.ModuleType(
        "server.modules.handlers.world.login.packets",
    )

    def capture_packet(_opcode, ctx):
        captured["player"] = ctx.player_runtime
        return b"create"

    packets_module.build_login_packet = capture_packet
    monkeypatch.setitem(
        sys.modules,
        "server.modules.handlers.world.login.packets",
        packets_module,
    )

    try:
        response = runtime._build_player_create_update_response(source)
    finally:
        store.clear()

    assert response == ("SMSG_UPDATE_OBJECT", b"create")
    assert captured["player"] is player
    assert captured["player"].runtime_guid == source.world_guid
