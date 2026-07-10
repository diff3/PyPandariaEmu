from __future__ import annotations

import math
import sys
import time
import types
from types import SimpleNamespace

database_module = types.ModuleType("server.modules.database.DatabaseConnection")
database_module.DatabaseConnection = type(
    "DatabaseConnection",
    (),
    {
        "get_gameobjects_near": staticmethod(lambda *args, **kwargs: []),
        "get_creatures_near": staticmethod(lambda *args, **kwargs: []),
        "get_areatrigger_teleport": staticmethod(lambda *args, **kwargs: None),
    },
)
sys.modules.setdefault("server.modules.database.DatabaseConnection", database_module)

from server.modules.handlers.world.collision.bounds import DisplayBounds, build_oriented_bounds
from server.modules.handlers.world.collision import geometry_shadow
from server.modules.handlers.world.collision.gameobject_collision import GameObjectCollision, gameobject_collision_index
from server.modules.handlers.world.collision.geometry import GeometryQuery, MeshAccelerator, Transform, Vec3, WorldGeometryMap, WorldMeshInstance
from server.modules.handlers.world.collision.geometry.manual_mesh_registry import (
    ONYXIA_TROPHY_DISPLAY_ID,
    ONYXIA_TROPHY_ENTRY,
    clear_manual_mesh_cache,
    get_manual_mesh_spec,
    load_manual_mesh_for_display,
)
from server.modules.handlers.world.collision.geometry_shadow import (
    clear_geometry_shadow_stats,
    _manual_trophy_miss_diagnostics_trigger,
    _box_mesh_for_half_extents,
    build_manual_trophy_authoritative_contact_probe,
    _collision_to_world_instance,
    _manual_mesh_transform_for_collision,
    format_geometry_shadow_stats_lines,
    get_geometry_shadow_stats,
    log_geometry_shadow_initialization,
    run_geometry_shadow_comparison,
)
from server.modules.handlers.world.opcodes import movement


def _bounds():
    return DisplayBounds((-1.0, -1.0, 0.0), (1.0, 1.0, 2.0))


def _collision_at(x: float) -> GameObjectCollision:
    bounds = build_oriented_bounds(_bounds(), position=(x, 0.0, 0.0), orientation=0.0, scale=1.0)
    assert bounds is not None
    return GameObjectCollision(1, 1200 + int(x * 10), 34, 56, bounds, "shadow-box")


def _trophy_display_bounds() -> DisplayBounds:
    return DisplayBounds((-4.0, -2.0, 0.0), (4.0, 2.0, 10.0))


def _live_trophy_display_bounds() -> DisplayBounds:
    return DisplayBounds(
        (-4.51025915145874, -5.935536861419678, -0.002859999891370535),
        (8.350172996520996, 6.813423156738281, 25.92267608642578),
    )


def _trophy_collision(
    *,
    position: tuple[float, float, float] = (10.0, 20.0, 30.0),
    orientation: float = 0.0,
    scale: float = 1.25,
) -> GameObjectCollision:
    bounds = build_oriented_bounds(
        _trophy_display_bounds(),
        position=position,
        orientation=orientation,
        scale=scale,
    )
    assert bounds is not None
    return GameObjectCollision(
        1,
        48216,
        ONYXIA_TROPHY_ENTRY,
        ONYXIA_TROPHY_DISPLAY_ID,
        bounds,
        "The Severed Head of Onyxia",
    )


def _live_trophy_collision() -> GameObjectCollision:
    bounds = build_oriented_bounds(
        _live_trophy_display_bounds(),
        position=(1520.56, -4392.79, 20.3804),
        orientation=4.85202,
        scale=1.25,
    )
    assert bounds is not None
    return GameObjectCollision(
        1,
        73357,
        ONYXIA_TROPHY_ENTRY,
        ONYXIA_TROPHY_DISPLAY_ID,
        bounds,
        "The Severed Head of Nefarian",
    )


def _logged_trophy_segments() -> tuple[tuple[tuple[float, float, float], tuple[float, float, float]], ...]:
    return (
        ((1525.785, -4397.448, 20.345), (1522.376, -4396.655, 20.779)),
        ((1525.582, -4397.401, 20.371), (1523.086, -4396.820, 20.642)),
        ((1525.574, -4397.399, 20.372), (1522.165, -4396.606, 20.821)),
        ((1525.574, -4397.399, 20.372), (1520.596, -4396.241, 21.134)),
    )


def _world_aabb_for_instance(instance: WorldMeshInstance) -> tuple[Vec3, Vec3]:
    mesh = instance.mesh
    assert mesh is not None
    corners = [
        instance.local_to_world(Vec3(x, y, z))
        for x in (mesh.aabb_min.x, mesh.aabb_max.x)
        for y in (mesh.aabb_min.y, mesh.aabb_max.y)
        for z in (mesh.aabb_min.z, mesh.aabb_max.z)
    ]
    min_corner = Vec3(
        min(point.x for point in corners),
        min(point.y for point in corners),
        min(point.z for point in corners),
    )
    max_corner = Vec3(
        max(point.x for point in corners),
        max(point.y for point in corners),
        max(point.z for point in corners),
    )
    return min_corner, max_corner


def test_shadow_mode_disabled_performs_no_geometry_queries(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_enabled", lambda: True
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_mode", lambda: "legacy"
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.geometry_shadow.run_geometry_shadow_comparison",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    session = SimpleNamespace(x=1.0, y=0.0, z=1.0, map_id=1, char_guid=99)
    assert movement._accept_movement_update(session, "MSG_MOVE_HEARTBEAT", 2.0, 0.0, 1.0, 0.0)
    assert calls == []


def test_shadow_mode_enabled_performs_comparison(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_enabled", lambda: True
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_mode", lambda: "shadow_compare"
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.geometry_shadow.run_geometry_shadow_comparison",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    session = SimpleNamespace(x=1.0, y=0.0, z=1.0, map_id=1, char_guid=99)
    assert movement._accept_movement_update(session, "MSG_MOVE_HEARTBEAT", 2.0, 0.0, 1.0, 0.0)
    assert len(calls) == 1
    _, kwargs = calls[0]
    assert kwargs["old_collision"] is None
    assert kwargs["old_resolved_end"] == (2.0, 0.0, 1.0)


def _shadow_result(
    *,
    old_hit: bool,
    new_hit: bool,
    resolved_end=(2.0, 0.0, 1.0),
    instance_id=0,
    normal=(-1.0, 0.0, 0.0),
):
    return SimpleNamespace(
        old_hit=old_hit,
        new_hit=new_hit,
        new_resolved_end=resolved_end,
        new_instance_id=instance_id,
        new_hit_normal=normal if new_hit else None,
        agreed=old_hit == new_hit,
    )


def _wall_contact(object_guid=101, *, created_at=None):
    from server.session.world_session import GeometryWallContact

    return GeometryWallContact(
        object_guid=object_guid,
        hit_normal=(-1.0, 0.0, 0.0),
        corrected_position=(2.0, 0.0, 1.0),
        created_at=time.monotonic() if created_at is None else created_at,
    )


def test_wall_contact_repeated_push_is_ignored_without_correction(monkeypatch):
    from server.session.world_session import MovementState

    gameobject_collision_index.clear()
    monkeypatch.setattr("server.modules.handlers.world.feature_config.gameobject_collision_enabled", lambda: True)
    monkeypatch.setattr("server.modules.handlers.world.feature_config.gameobject_collision_mode", lambda: "shadow_authoritative")
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.geometry_shadow.run_geometry_shadow_comparison",
        lambda *args, **kwargs: _shadow_result(
            old_hit=False, new_hit=True, resolved_end=(2.0, 0.0, 1.0), instance_id=101
        ),
    )
    state = MovementState(geometry_wall_contact=_wall_contact())
    session = SimpleNamespace(x=2.0, y=0.0, z=1.0, map_id=1, char_guid=99, movement_state=state)

    assert movement._accept_movement_update(session, "MSG_MOVE_HEARTBEAT", 3.0, 0.0, 1.0, 0.0) is False
    assert session._last_movement_rejection == "gameobject_wall_contact"
    assert session._last_collision_correction is None
    assert movement._build_collision_reject_responses(session, "MSG_MOVE_HEARTBEAT") == []


def test_wall_contact_moving_away_clears_contact(monkeypatch):
    from server.session.world_session import MovementState

    state = MovementState(geometry_wall_contact=_wall_contact())
    session = SimpleNamespace(movement_state=state)
    contact, reason = movement._active_geometry_wall_contact(
        session, (2.0, 0.0, 1.0), (1.0, 0.0, 1.0), now=state.geometry_wall_contact.created_at
    )
    assert contact is None
    assert reason == "released"
    assert state.geometry_wall_contact is None


def test_wall_contact_different_object_gets_new_correction(monkeypatch):
    from server.session.world_session import MovementState

    gameobject_collision_index.clear()
    monkeypatch.setattr("server.modules.handlers.world.feature_config.gameobject_collision_enabled", lambda: True)
    monkeypatch.setattr("server.modules.handlers.world.feature_config.gameobject_collision_mode", lambda: "shadow_authoritative")
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.geometry_shadow.run_geometry_shadow_comparison",
        lambda *args, **kwargs: _shadow_result(
            old_hit=False, new_hit=True, resolved_end=(2.5, 0.0, 1.0), instance_id=202
        ),
    )
    state = MovementState(geometry_wall_contact=_wall_contact(object_guid=101))
    session = SimpleNamespace(x=2.0, y=0.0, z=1.0, map_id=1, char_guid=99, movement_state=state)

    assert movement._accept_movement_update(session, "MSG_MOVE_HEARTBEAT", 3.0, 0.0, 1.0, 0.0) is False
    assert session._last_movement_rejection == "gameobject_collision"
    assert session._last_collision_correction == (2.5, 0.0, 1.0, 0.0)
    movement._install_pending_geometry_wall_contact(session, now=20.0)
    assert state.geometry_wall_contact.object_guid == 202


def test_wall_contact_timeout_clears_contact():
    from server.session.world_session import MovementState

    state = MovementState(geometry_wall_contact=_wall_contact(created_at=10.0))
    session = SimpleNamespace(movement_state=state)
    contact, reason = movement._active_geometry_wall_contact(
        session,
        (2.0, 0.0, 1.0),
        (3.0, 0.0, 1.0),
        now=10.0 + movement._GEOMETRY_WALL_CONTACT_TIMEOUT_SECONDS,
    )
    assert contact is None
    assert reason == "expired"
    assert state.geometry_wall_contact is None


def test_collision_mode_legacy_uses_legacy_only(monkeypatch):
    gameobject_collision_index.clear()
    gameobject_collision_index.register(_collision_at(4.0))
    calls = []
    monkeypatch.setattr("server.modules.handlers.world.feature_config.gameobject_collision_enabled", lambda: True)
    monkeypatch.setattr("server.modules.handlers.world.feature_config.gameobject_collision_mode", lambda: "legacy")
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.geometry_shadow.run_geometry_shadow_comparison",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    session = SimpleNamespace(x=1.0, y=0.0, z=1.0, map_id=1, char_guid=99)
    assert movement._accept_movement_update(session, "MSG_MOVE_HEARTBEAT", 4.0, 0.0, 1.0, 0.0) is False
    assert calls == []


def test_collision_mode_shadow_compare_keeps_legacy_authoritative(monkeypatch):
    gameobject_collision_index.clear()
    gameobject_collision_index.register(_collision_at(4.0))
    monkeypatch.setattr("server.modules.handlers.world.feature_config.gameobject_collision_enabled", lambda: True)
    monkeypatch.setattr("server.modules.handlers.world.feature_config.gameobject_collision_mode", lambda: "shadow_compare")
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.geometry_shadow.run_geometry_shadow_comparison",
        lambda *args, **kwargs: _shadow_result(old_hit=True, new_hit=False),
    )

    session = SimpleNamespace(x=1.0, y=0.0, z=1.0, map_id=1, char_guid=99)
    assert movement._accept_movement_update(session, "MSG_MOVE_HEARTBEAT", 4.0, 0.0, 1.0, 0.0) is False
    assert session._last_collision_correction is not None


def test_collision_mode_shadow_authoritative_uses_shadow_only(monkeypatch):
    gameobject_collision_index.clear()
    gameobject_collision_index.register(_collision_at(4.0))
    monkeypatch.setattr("server.modules.handlers.world.feature_config.gameobject_collision_enabled", lambda: True)
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_mode",
        lambda: "shadow_authoritative",
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.geometry_shadow.run_geometry_shadow_comparison",
        lambda *args, **kwargs: _shadow_result(old_hit=True, new_hit=False, resolved_end=(4.0, 0.0, 1.0)),
    )

    session = SimpleNamespace(x=1.0, y=0.0, z=1.0, map_id=1, char_guid=99)
    assert movement._accept_movement_update(session, "MSG_MOVE_HEARTBEAT", 4.0, 0.0, 1.0, 0.0) is True
    assert session._last_collision_correction is None

    gameobject_collision_index.clear()
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.geometry_shadow.run_geometry_shadow_comparison",
        lambda *args, **kwargs: _shadow_result(old_hit=False, new_hit=True, resolved_end=(2.5, 0.0, 1.0)),
    )
    session = SimpleNamespace(x=1.0, y=0.0, z=1.0, map_id=1, char_guid=99)
    assert movement._accept_movement_update(session, "MSG_MOVE_HEARTBEAT", 4.0, 0.0, 1.0, 0.0) is False
    assert session._last_collision_correction == (2.5, 0.0, 1.0, 0.0)


def test_shadow_authoritative_logs_legacy_disagreement_as_diagnostic(monkeypatch):
    gameobject_collision_index.clear()
    gameobject_collision_index.register(_collision_at(4.0))
    captured = []
    monkeypatch.setattr("server.modules.handlers.world.feature_config.gameobject_collision_enabled", lambda: True)
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_mode",
        lambda: "shadow_authoritative",
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.geometry_shadow.run_geometry_shadow_comparison",
        lambda *args, **kwargs: _shadow_result(old_hit=True, new_hit=False, resolved_end=(4.0, 0.0, 1.0)),
    )
    monkeypatch.setattr(movement.Logger, "info", lambda message, *args: captured.append(message % args if args else message))

    session = SimpleNamespace(x=1.0, y=0.0, z=1.0, map_id=1, char_guid=99)
    assert movement._accept_movement_update(session, "MSG_MOVE_HEARTBEAT", 4.0, 0.0, 1.0, 0.0) is True
    assert any(
        "diagnostic_only=true legacy_hit=true shadow_hit=false" in line
        for line in captured
    )


def test_shadow_authoritative_legacy_only_hit_sends_no_correction_packets(monkeypatch):
    gameobject_collision_index.clear()
    gameobject_collision_index.register(_collision_at(4.0))
    monkeypatch.setattr("server.modules.handlers.world.feature_config.gameobject_collision_enabled", lambda: True)
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_mode",
        lambda: "shadow_authoritative",
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.geometry_shadow.run_geometry_shadow_comparison",
        lambda *args, **kwargs: _shadow_result(old_hit=True, new_hit=False, resolved_end=(4.0, 0.0, 1.0)),
    )

    session = SimpleNamespace(x=1.0, y=0.0, z=1.0, map_id=1, char_guid=99)
    assert movement._accept_movement_update(session, "MSG_MOVE_HEARTBEAT", 4.0, 0.0, 1.0, 0.0) is True
    assert movement._build_collision_reject_responses(session, "MSG_MOVE_HEARTBEAT") == []


def test_shadow_mode_never_changes_authoritative_accept_result(monkeypatch):
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_enabled", lambda: True
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_mode", lambda: "legacy"
    )
    session = SimpleNamespace(x=1.0, y=0.0, z=1.0, map_id=1, char_guid=99)
    without_shadow = movement._accept_movement_update(session, "MSG_MOVE_HEARTBEAT", 2.0, 0.0, 1.0, 0.0)

    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_mode", lambda: "shadow_compare"
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.geometry_shadow.run_geometry_shadow_comparison",
        lambda *args, **kwargs: {"shadow": True},
    )
    session2 = SimpleNamespace(x=1.0, y=0.0, z=1.0, map_id=1, char_guid=99)
    with_shadow = movement._accept_movement_update(session2, "MSG_MOVE_HEARTBEAT", 2.0, 0.0, 1.0, 0.0)

    assert without_shadow is True
    assert with_shadow is True


def test_shadow_mode_never_changes_player_position_or_packets(monkeypatch):
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_enabled", lambda: True
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_mode", lambda: "legacy"
    )
    monkeypatch.setattr(
        movement,
        "parse_movement_info",
        lambda *args, **kwargs: (2.0, 0.0, 1.0, 0.0),
    )
    monkeypatch.setattr(movement, "_maybe_stream_world_objects", lambda session: [])
    monkeypatch.setattr(movement, "_maybe_start_transport_route_transfer", lambda session, opcode_name: [])
    monkeypatch.setattr(movement, "_maybe_move_companion_pet_for_opcode", lambda session, opcode_name: [])
    monkeypatch.setattr(movement, "_maybe_discover_current_area", lambda session: [])
    monkeypatch.setattr(movement, "broadcast_player_state_update", lambda session, force=False: None)
    session = SimpleNamespace(
        x=1.0,
        y=0.0,
        z=1.0,
        orientation=0.0,
        map_id=1,
        char_guid=99,
        movement_state=SimpleNamespace(flags=0, flags2=0, counter=0),
    )
    ctx = SimpleNamespace(name="MSG_MOVE_HEARTBEAT", opcode=0x01, payload=b"", decoded={})
    code_off, responses_off = movement.handle_movement_packet(session, ctx)
    off_position = (session.x, session.y, session.z, session.orientation)

    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_mode", lambda: "shadow_compare"
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.geometry_shadow.run_geometry_shadow_comparison",
        lambda *args, **kwargs: {"shadow": True},
    )
    session2 = SimpleNamespace(
        x=1.0,
        y=0.0,
        z=1.0,
        orientation=0.0,
        map_id=1,
        char_guid=99,
        movement_state=SimpleNamespace(flags=0, flags2=0, counter=0),
    )
    code_on, responses_on = movement.handle_movement_packet(session2, ctx)
    on_position = (session2.x, session2.y, session2.z, session2.orientation)

    assert code_off == code_on
    assert responses_off == responses_on
    assert off_position == on_position


def test_shadow_statistics_counters_update_correctly(monkeypatch):
    clear_geometry_shadow_stats()
    gameobject_collision_index.clear()
    gameobject_collision_index.register(_collision_at(4.0))

    session = SimpleNamespace(char_guid=99)
    comparison = run_geometry_shadow_comparison(
        session,
        "MSG_MOVE_HEARTBEAT",
        map_id=1,
        start=(0.0, 0.0, 1.0),
        end=(8.0, 0.0, 1.0),
        old_collision=_collision_at(4.0),
        old_resolved_end=(2.99, 0.0, 1.0),
        authoritative_mode="shadow_authoritative",
    )

    stats = get_geometry_shadow_stats()
    assert comparison.old_hit is True
    assert comparison.new_hit is True
    assert int(stats["comparisons"]) == 1
    assert int(stats["agreements"]) == 1
    assert int(stats["old_hit_new_hit"]) == 1
    assert stats["authoritative_mode"] == "shadow_authoritative"
    assert int(stats["legacy_hits"]) == 1
    assert int(stats["shadow_hits"]) == 1
    assert int(stats["legacy_only"]) == 0
    assert int(stats["shadow_only"]) == 0
    assert int(stats["both_hit"]) == 1
    assert int(stats["both_miss"]) == 0
    assert float(stats["average_delta"]) >= 0.0
    assert any("comparisons=1" in line for line in format_geometry_shadow_stats_lines())


def test_shadow_contact_resolution_uses_configured_hit_normal_separation(monkeypatch):
    clear_geometry_shadow_stats()
    gameobject_collision_index.clear()
    collision = _collision_at(4.0)
    gameobject_collision_index.register(collision)
    monkeypatch.setattr(geometry_shadow, "_world_cache", None)
    monkeypatch.setattr(geometry_shadow, "_world_cache_signature", None)
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.geometry_contact_separation_epsilon",
        lambda: 0.05,
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_debug_enabled",
        lambda: True,
    )
    captured = []
    monkeypatch.setattr(
        geometry_shadow.Logger,
        "info",
        lambda message, *args: captured.append(message % args if args else message),
    )

    comparison = run_geometry_shadow_comparison(
        SimpleNamespace(char_guid=99),
        "MSG_MOVE_HEARTBEAT",
        map_id=1,
        start=(0.0, 0.0, 1.0),
        end=(8.0, 0.0, 1.0),
        old_collision=collision,
        old_resolved_end=(2.95, 0.0, 1.0),
        authoritative_mode="shadow_authoritative",
    )

    assert comparison.new_hit is True
    hit = Vec3(*comparison.new_hit_position)
    normal = Vec3(*comparison.new_hit_normal)
    corrected = Vec3(*comparison.new_resolved_end)
    assert corrected == hit + (normal * 0.05)
    assert corrected != hit
    assert math.isclose((corrected - hit).length(), 0.05, abs_tol=1e-9)
    assert any(
        "[GeometryShadow] contact_resolution" in line
        and "epsilon=0.050000" in line
        and "separation_distance=0.050000" in line
        for line in captured
    )


def test_manual_trophy_authoritative_contact_probe_reports_containment(monkeypatch):
    gameobject_collision_index.clear()
    collision = _live_trophy_collision()
    gameobject_collision_index.register(collision)
    monkeypatch.setattr(geometry_shadow, "_world_cache", None)
    monkeypatch.setattr(geometry_shadow, "_world_cache_signature", None)
    start, end = _logged_trophy_segments()[3]

    comparison = run_geometry_shadow_comparison(
        SimpleNamespace(char_guid=99),
        "MSG_MOVE_HEARTBEAT",
        map_id=1,
        start=start,
        end=end,
        old_collision=collision,
        old_resolved_end=start,
        authoritative_mode="shadow_authoritative",
    )
    probe = build_manual_trophy_authoritative_contact_probe(1, comparison)

    assert probe is not None
    assert probe["guid"] == 73357
    assert probe["entry"] == 179881
    assert probe["display_id"] == 5951
    assert probe["mesh"] == "manual_onyxia_trophy_5951"
    assert math.isclose(float(probe["separation_distance"]), 0.05, abs_tol=1e-9)
    assert isinstance(probe["corrected_inside_world_aabb"], bool)
    assert isinstance(probe["corrected_inside_legacy_obb"], bool)


def test_geometry_shadow_contact_probe_correlates_next_packet(monkeypatch):
    captured = []
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_debug_enabled",
        lambda: True,
    )
    monkeypatch.setattr(
        movement.Logger,
        "info",
        lambda message, *args: captured.append(message % args if args else message),
    )
    session = SimpleNamespace(
        _geometry_shadow_contact_probe={
            "collision_id": "16-7",
            "guid": 73357,
            "entry": 179881,
            "display_id": 5951,
            "mesh": "manual_onyxia_trophy_5951",
            "hit_position": (1.0, 2.0, 3.0),
            "corrected_position": (1.05, 2.0, 3.0),
        }
    )

    movement._consume_geometry_shadow_contact_probe(
        session,
        "MSG_MOVE_HEARTBEAT",
        (1.05, 2.0, 3.0),
        flags=1,
        flags2=0,
    )

    assert session._geometry_shadow_contact_probe is None
    assert any(
        "collision_id=16-7" in line
        and "next_opcode=MSG_MOVE_HEARTBEAT" in line
        and "distance_to_corrected=0.000000" in line
        and "distance_to_hit=0.050000" in line
        for line in captured
    )


def test_manual_trophy_miss_diagnostics_are_emitted_only_for_trophy_old_hit_new_miss(monkeypatch):
    clear_geometry_shadow_stats()
    clear_manual_mesh_cache()
    gameobject_collision_index.clear()
    gameobject_collision_index.register(_live_trophy_collision())
    monkeypatch.setattr(geometry_shadow, "_world_cache", None)
    monkeypatch.setattr(geometry_shadow, "_world_cache_signature", None)
    monkeypatch.setattr(geometry_shadow, "_display_bounds_cache", None)
    geometry_shadow._manual_mesh_logged.clear()
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.geometry_shadow._shadow_display_bounds_by_display",
        lambda: {ONYXIA_TROPHY_DISPLAY_ID: _live_trophy_display_bounds()},
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_debug_enabled",
        lambda: True,
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.experimental_geometry_shadow_enabled",
        lambda: True,
    )
    captured = []
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.geometry_shadow.Logger.info",
        lambda message, *args: captured.append(message % args if args else message),
    )

    comparison = run_geometry_shadow_comparison(
        SimpleNamespace(char_guid=99),
        "MSG_MOVE_STOP",
        map_id=1,
        start=_logged_trophy_segments()[0][0],
        end=_logged_trophy_segments()[0][1],
        old_collision=_live_trophy_collision(),
        old_resolved_end=_logged_trophy_segments()[0][0],
    )

    assert comparison.old_hit is True
    assert comparison.new_hit is False
    assert any("trophy_trigger entered enabled=true old_hit=true new_hit=false old_collision=yes entry=179881 displayId=5951 guid=73357" in line for line in captured)
    assert any("trophy_trigger result=true registry_match=true mesh=manual_onyxia_trophy_5951 reason=ok" in line for line in captured)
    assert any("trophy_miss opcode=MSG_MOVE_STOP" in line for line in captured)
    assert any("trophy_miss legacy_obb center=" in line for line in captured)
    assert any("trophy_miss transform translation=" in line for line in captured)
    assert any("trophy_miss local_aabb min=" in line for line in captured)
    assert any("trophy_miss query world_aabb_intersected=" in line for line in captured)
    assert any("trophy_miss bvh nearest_node_entry=" in line for line in captured)
    assert any("trophy_miss bvh_result stop_reason=" in line for line in captured)
    assert any("trophy_miss bvh_trace step=0" in line for line in captured)
    assert any("manual_trophy_old_hit_new_miss total=1" in line for line in format_geometry_shadow_stats_lines())


def test_manual_trophy_miss_trigger_exposes_each_predicate_component():
    comparison = geometry_shadow.GeometryShadowComparison(
        old_hit=True,
        old_collision=_live_trophy_collision(),
        old_resolved_end=_logged_trophy_segments()[0][0],
        new_hit=False,
        new_resolved_end=_logged_trophy_segments()[0][0],
        new_fraction=None,
        new_hit_position=None,
        new_hit_normal=None,
        new_mesh_name=None,
        new_instance_id=None,
        delta=1.0,
        agreed=False,
    )

    trigger = _manual_trophy_miss_diagnostics_trigger(comparison, enabled=True)

    assert trigger["enabled"] is True
    assert trigger["old_hit"] is True
    assert trigger["new_hit"] is False
    assert trigger["has_old_collision"] is True
    assert trigger["entry"] == 179881
    assert trigger["display_id"] == 5951
    assert trigger["guid"] == 73357
    assert trigger["manual_mesh_name"] == "manual_onyxia_trophy_5951"
    assert trigger["comparison_new_mesh_name"] is None
    assert trigger["entry_matches"] is True
    assert trigger["display_id_matches"] is True
    assert trigger["manual_mesh_matches"] is True
    assert trigger["should_log"] is True


def test_manual_trophy_miss_trigger_is_disabled_when_gameobject_collision_debug_is_false():
    comparison = geometry_shadow.GeometryShadowComparison(
        old_hit=True,
        old_collision=_live_trophy_collision(),
        old_resolved_end=_logged_trophy_segments()[0][0],
        new_hit=False,
        new_resolved_end=_logged_trophy_segments()[0][0],
        new_fraction=None,
        new_hit_position=None,
        new_hit_normal=None,
        new_mesh_name=None,
        new_instance_id=None,
        delta=1.0,
        agreed=False,
    )

    trigger = _manual_trophy_miss_diagnostics_trigger(comparison, enabled=False)

    assert trigger["enabled"] is False
    assert trigger["entry_matches"] is True
    assert trigger["display_id_matches"] is True
    assert trigger["manual_mesh_matches"] is True
    assert trigger["should_log"] is False
    assert trigger["reason"] == "debug_disabled"


def test_manual_trophy_miss_diagnostics_not_emitted_for_non_trophy_old_hit_new_miss(monkeypatch):
    clear_geometry_shadow_stats()
    gameobject_collision_index.clear()
    monkeypatch.setattr(geometry_shadow, "_world_cache", None)
    monkeypatch.setattr(geometry_shadow, "_world_cache_signature", None)
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_debug_enabled",
        lambda: True,
    )
    captured = []
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.geometry_shadow.Logger.info",
        lambda message, *args: captured.append(message % args if args else message),
    )

    comparison = run_geometry_shadow_comparison(
        SimpleNamespace(char_guid=99),
        "MSG_MOVE_STOP",
        map_id=1,
        start=(0.0, 0.0, 1.0),
        end=(1.0, 0.0, 1.0),
        old_collision=_collision_at(4.0),
        old_resolved_end=(0.0, 0.0, 1.0),
    )

    assert comparison.old_hit is True
    assert comparison.new_hit is False
    assert not any("trophy_miss " in line for line in captured)
    assert not any("manual_trophy_old_hit_new_miss" in line for line in format_geometry_shadow_stats_lines())


def test_manual_trophy_miss_diagnostics_do_not_change_shadow_statistics_and_can_be_disabled(monkeypatch):
    def _run(debug_enabled: bool):
        clear_geometry_shadow_stats()
        clear_manual_mesh_cache()
        gameobject_collision_index.clear()
        gameobject_collision_index.register(_live_trophy_collision())
        monkeypatch.setattr(geometry_shadow, "_world_cache", None)
        monkeypatch.setattr(geometry_shadow, "_world_cache_signature", None)
        monkeypatch.setattr(geometry_shadow, "_display_bounds_cache", None)
        geometry_shadow._manual_mesh_logged.clear()
        monkeypatch.setattr(
            "server.modules.handlers.world.collision.geometry_shadow._shadow_display_bounds_by_display",
            lambda: {ONYXIA_TROPHY_DISPLAY_ID: _live_trophy_display_bounds()},
        )
        monkeypatch.setattr(
            "server.modules.handlers.world.feature_config.gameobject_collision_debug_enabled",
            lambda: debug_enabled,
        )
        captured = []
        monkeypatch.setattr(
            "server.modules.handlers.world.collision.geometry_shadow.Logger.info",
            lambda message, *args: captured.append(message % args if args else message),
        )
        run_geometry_shadow_comparison(
            SimpleNamespace(char_guid=99),
            "MSG_MOVE_STOP",
            map_id=1,
            start=_logged_trophy_segments()[0][0],
            end=_logged_trophy_segments()[0][1],
            old_collision=_live_trophy_collision(),
            old_resolved_end=_logged_trophy_segments()[0][0],
        )
        return get_geometry_shadow_stats(), list(format_geometry_shadow_stats_lines()), captured

    stats_disabled, lines_disabled, captured_disabled = _run(False)
    stats_enabled, lines_enabled, captured_enabled = _run(True)

    assert stats_disabled == stats_enabled
    assert any("trophy_trigger entered enabled=false old_hit=true new_hit=false old_collision=yes entry=179881 displayId=5951 guid=73357" in line for line in captured_disabled)
    assert any("trophy_trigger result=false registry_match=true mesh=manual_onyxia_trophy_5951 reason=debug_disabled" in line for line in captured_disabled)
    assert not any("trophy_miss " in line for line in captured_disabled)
    assert not any("manual_trophy_old_hit_new_miss" in line for line in lines_disabled)
    assert any("trophy_trigger entered enabled=true old_hit=true new_hit=false old_collision=yes entry=179881 displayId=5951 guid=73357" in line for line in captured_enabled)
    assert any("trophy_trigger result=true registry_match=true mesh=manual_onyxia_trophy_5951 reason=ok" in line for line in captured_enabled)
    assert any("trophy_miss " in line for line in captured_enabled)
    assert any("manual_trophy_old_hit_new_miss total=1" in line for line in lines_enabled)


def test_run_geometry_shadow_comparison_calls_trophy_diagnostic_function(monkeypatch):
    clear_geometry_shadow_stats()
    calls = []
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.geometry_shadow._get_or_build_shadow_world",
        lambda: object(),
    )
    from types import SimpleNamespace as _SN
    from server.modules.handlers.world.collision.geometry import Vec3
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_debug_enabled",
        lambda: True,
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.geometry_shadow._maybe_log_comparison",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.geometry_shadow._maybe_log_manual_trophy_miss_diagnostics",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    class _Result:
        hit = None
        resolved_end = Vec3(*_logged_trophy_segments()[0][0])
        fraction = 1.0
        hit_position = None
        hit_normal = None
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.geometry.resolve_segment",
        lambda start, end, world, **kwargs: _Result(),
    )

    run_geometry_shadow_comparison(
        _SN(char_guid=99),
        "MSG_MOVE_STOP",
        map_id=1,
        start=_logged_trophy_segments()[0][0],
        end=_logged_trophy_segments()[0][1],
        old_collision=_live_trophy_collision(),
        old_resolved_end=_logged_trophy_segments()[0][0],
    )

    assert len(calls) == 1


def test_shadow_initialization_logs_enabled_state(monkeypatch):
    captured = []
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_mode",
        lambda: "shadow_compare",
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_debug_enabled",
        lambda: True,
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.geometry_shadow.Logger.info",
        lambda message, *args: captured.append(message % args if args else message),
    )

    log_geometry_shadow_initialization()

    assert captured == [
        "[GeometryShadow] ExperimentalGeometryShadow=true",
        "[GeometryShadow] GameObjectCollisionMode=shadow_compare",
        "[GeometryShadow] Legacy collision authoritative=true",
        "[GeometryShadow] Geometry Shadow authoritative=false",
        "[GeometryShadow] initialized enabled=true",
        "[GeometryShadow] startup shadow=true debug=true authoritative_mode=shadow_compare",
    ]


def test_shadow_initialization_logs_authoritative_mode(monkeypatch):
    captured = []
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_mode",
        lambda: "shadow_authoritative",
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.experimental_geometry_shadow_enabled",
        lambda: True,
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_debug_enabled",
        lambda: False,
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.geometry_shadow.Logger.info",
        lambda message, *args: captured.append(message % args if args else message),
    )

    log_geometry_shadow_initialization()

    assert "[GeometryShadow] ExperimentalGeometryShadow=true" in captured
    assert "[GeometryShadow] GameObjectCollisionMode=shadow_authoritative" in captured
    assert "[GeometryShadow] Legacy collision authoritative=false" in captured
    assert "[GeometryShadow] Geometry Shadow authoritative=true" in captured


def test_manual_mesh_registry_lookup_returns_trophy_spec():
    spec = get_manual_mesh_spec(ONYXIA_TROPHY_DISPLAY_ID)

    assert spec is not None
    assert spec.display_id == ONYXIA_TROPHY_DISPLAY_ID
    assert spec.entry == ONYXIA_TROPHY_ENTRY
    assert spec.mesh_name == "manual_onyxia_trophy_5951"


def test_manual_mesh_loads_correctly():
    clear_manual_mesh_cache()

    mesh = load_manual_mesh_for_display(ONYXIA_TROPHY_DISPLAY_ID)

    assert mesh is not None
    assert mesh.name == "manual_onyxia_trophy_5951"
    assert len(mesh.triangles) == 60
    assert mesh.aabb_min.x < 0.0 < mesh.aabb_max.x
    assert mesh.aabb_min.y < 0.0 < mesh.aabb_max.y
    assert mesh.aabb_min.z == 0.0
    assert mesh.aabb_max.z > 10.0


def test_manual_mesh_participates_in_world_geometry_map(monkeypatch):
    clear_manual_mesh_cache()
    mesh = load_manual_mesh_for_display(ONYXIA_TROPHY_DISPLAY_ID)
    assert mesh is not None
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.geometry_shadow._shadow_display_bounds_by_display",
        lambda: {ONYXIA_TROPHY_DISPLAY_ID: _trophy_display_bounds()},
    )

    instance = _collision_to_world_instance(_trophy_collision(position=(0.0, 0.0, 0.0), scale=1.0))
    world = WorldGeometryMap([instance])
    hit = GeometryQuery(world).raycast(Vec3(0.0, -10.0, 5.0), Vec3(0.0, 10.0, 5.0))

    assert hit is not None
    assert hit.mesh is not None
    assert hit.mesh.name == "manual_onyxia_trophy_5951"
    assert hit.instance is instance


def test_shadow_mode_selects_manual_mesh_for_trophy(monkeypatch):
    clear_manual_mesh_cache()
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.geometry_shadow._shadow_display_bounds_by_display",
        lambda: {ONYXIA_TROPHY_DISPLAY_ID: _trophy_display_bounds()},
    )

    instance = _collision_to_world_instance(_trophy_collision(position=(10.0, 20.0, 30.0), orientation=0.5, scale=1.25))

    assert instance.mesh is not None
    assert instance.mesh.name == "manual_onyxia_trophy_5951"
    assert instance.transform.scale == 1.25
    assert round(instance.transform.translation.x, 3) == 10.0
    assert round(instance.transform.translation.y, 3) == 20.0
    assert round(instance.transform.translation.z, 3) == 30.0


def test_shadow_mode_falls_back_to_obb_when_no_manual_mesh_exists():
    instance = _collision_to_world_instance(_collision_at(4.0))

    assert instance.mesh is not None
    assert instance.mesh.name.startswith("obb_")
    assert instance.transform.scale == 1.0


def test_shadow_mode_falls_back_to_obb_when_manual_mesh_transform_is_unavailable(monkeypatch):
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.geometry_shadow._shadow_display_bounds_by_display",
        lambda: {},
    )

    instance = _collision_to_world_instance(_trophy_collision())

    assert instance.mesh is not None
    assert instance.mesh.name.startswith("obb_")
    assert instance.transform.scale == 1.0


def test_live_trophy_manual_mesh_is_narrower_and_shorter_than_legacy_obb():
    collision = _live_trophy_collision()
    manual_mesh = load_manual_mesh_for_display(ONYXIA_TROPHY_DISPLAY_ID)
    assert manual_mesh is not None

    manual_transform = _manual_mesh_transform_for_collision(collision)
    assert manual_transform is not None
    manual_instance = WorldMeshInstance(provider=MeshAccelerator(manual_mesh), transform=manual_transform, instance_id=73357)
    box_instance = WorldMeshInstance(
        provider=MeshAccelerator(_box_mesh_for_half_extents(collision.bounds.half_extents)),
        transform=Transform(
            translation=Vec3(*collision.bounds.center),
            rotation_yaw=float(collision.bounds.orientation),
            scale=1.0,
        ),
        instance_id=73357,
    )

    manual_min, manual_max = _world_aabb_for_instance(manual_instance)
    box_min, box_max = _world_aabb_for_instance(box_instance)

    assert manual_transform.translation == Vec3(1520.56, -4392.79, 20.3804)
    assert round(box_min.z, 3) == 20.377
    assert round(box_max.z, 3) == 52.784
    assert round(manual_min.z, 3) == 20.380
    assert round(manual_max.z, 3) == 35.130
    assert (manual_max.z - manual_min.z) < (box_max.z - box_min.z)
    assert (manual_max.x - manual_min.x) < (box_max.x - box_min.x)
    assert (manual_max.y - manual_min.y) < (box_max.y - box_min.y)


def test_logged_trophy_segments_hit_legacy_obb_and_generated_box_mesh_but_not_shallow_manual_mesh():
    collision = _live_trophy_collision()
    manual_mesh = load_manual_mesh_for_display(ONYXIA_TROPHY_DISPLAY_ID)
    assert manual_mesh is not None

    manual_transform = _manual_mesh_transform_for_collision(collision)
    assert manual_transform is not None
    manual_world = WorldGeometryMap(
        [WorldMeshInstance(provider=MeshAccelerator(manual_mesh), transform=manual_transform, instance_id=73357)]
    )
    box_world = WorldGeometryMap(
        [
            WorldMeshInstance(
                provider=MeshAccelerator(_box_mesh_for_half_extents(collision.bounds.half_extents)),
                transform=Transform(
                    translation=Vec3(*collision.bounds.center),
                    rotation_yaw=float(collision.bounds.orientation),
                    scale=1.0,
                ),
                instance_id=73357,
            )
        ]
    )

    segments = _logged_trophy_segments()
    for start, end in segments[:3]:
        assert collision.bounds.intersects_segment(start, end) is True
        box_hit = GeometryQuery(box_world).raycast(Vec3(*start), Vec3(*end))
        manual_hit = GeometryQuery(manual_world).raycast(Vec3(*start), Vec3(*end))
        assert box_hit is not None
        assert manual_hit is None
        assert float(box_hit.fraction) < 0.1


def test_deep_logged_trophy_segment_hits_manual_mesh_much_later_than_legacy_obb():
    collision = _live_trophy_collision()
    manual_mesh = load_manual_mesh_for_display(ONYXIA_TROPHY_DISPLAY_ID)
    assert manual_mesh is not None

    manual_transform = _manual_mesh_transform_for_collision(collision)
    assert manual_transform is not None
    manual_world = WorldGeometryMap(
        [WorldMeshInstance(provider=MeshAccelerator(manual_mesh), transform=manual_transform, instance_id=73357)]
    )
    box_world = WorldGeometryMap(
        [
            WorldMeshInstance(
                provider=MeshAccelerator(_box_mesh_for_half_extents(collision.bounds.half_extents)),
                transform=Transform(
                    translation=Vec3(*collision.bounds.center),
                    rotation_yaw=float(collision.bounds.orientation),
                    scale=1.0,
                ),
                instance_id=73357,
            )
        ]
    )

    start, end = _logged_trophy_segments()[3]
    legacy_fraction = collision.bounds.segment_intersection_fraction(start, end)
    box_hit = GeometryQuery(box_world).raycast(Vec3(*start), Vec3(*end))
    manual_hit = GeometryQuery(manual_world).raycast(Vec3(*start), Vec3(*end))

    assert legacy_fraction is not None
    assert box_hit is not None
    assert manual_hit is not None
    assert float(legacy_fraction) < 0.01
    assert float(box_hit.fraction) < 0.01
    assert float(manual_hit.fraction) > 0.8
