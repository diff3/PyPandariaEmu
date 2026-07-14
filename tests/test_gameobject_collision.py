from __future__ import annotations

import math
import sys
import types
from types import SimpleNamespace

from server.modules.handlers.world.collision.bounds import DisplayBounds, build_oriented_bounds
from server.modules.handlers.world.collision.gameobject_collision import (
    GameObjectCollision,
    GameObjectCollisionIndex,
    build_gameobject_collision,
    build_gameobject_collision_index,
    gameobject_collision_index,
    gameobject_is_eligible,
)
from server.modules.handlers.world.runtime.gameobject import GameObject
from server.modules.handlers.world.runtime.gameobject_store import (
    get_gameobject_runtime_store,
)

# The focused movement test does not require a live SQLAlchemy/world DB stack.
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

from server.modules.handlers.world.opcodes import movement


def _display_bounds() -> DisplayBounds:
    return DisplayBounds((-1.0, -0.5, 0.0), (1.0, 0.5, 2.0))


def _entry(**overrides) -> dict:
    entry = {
        "guid": 12,
        "entry": 34,
        "map_id": 1,
        "type": 3,
        "display_id": 56,
        "state": 1,
        "flags": 0,
        "size": 1.0,
        "x": 4.0,
        "y": 0.0,
        "z": 0.0,
        "orientation": 0.0,
    }
    entry.update(overrides)
    return entry


def test_build_collision_bounds_applies_display_center_scale_and_position():
    bounds = build_oriented_bounds(
        DisplayBounds((-2.0, -1.0, 0.0), (4.0, 3.0, 6.0)),
        position=(10.0, 20.0, 30.0),
        orientation=0.0,
        scale=0.5,
    )
    assert bounds is not None
    assert bounds.center == (10.5, 20.5, 31.5)
    assert bounds.half_extents == (1.5, 1.0, 1.5)


def test_rotated_bounds_contains_only_points_inside_rotated_shape():
    bounds = build_oriented_bounds(
        _display_bounds(), position=(0.0, 0.0, 0.0), orientation=math.pi / 2, scale=1.0
    )
    assert bounds is not None
    assert bounds.contains((0.0, 0.9, 1.0))
    assert not bounds.contains((0.9, 0.0, 1.0))


def test_containment_fraction_increases_toward_boundary():
    bounds = build_oriented_bounds(
        _display_bounds(), position=(0.0, 0.0, 0.0), orientation=0.0, scale=1.0
    )
    assert bounds is not None
    assert bounds.containment_fraction((0.0, 0.0, 1.0)) < bounds.containment_fraction((0.9, 0.0, 1.0))
    assert bounds.containment_fraction((1.0, 0.0, 1.0)) == 1.0


def test_wireframe_points_follow_same_oriented_bounds_rotation():
    bounds = build_oriented_bounds(
        DisplayBounds((-1.0, -1.0, 0.0), (1.0, 1.0, 2.0)),
        position=(10.0, 20.0, 30.0),
        orientation=math.pi / 4.0,
        scale=1.0,
    )
    assert bounds is not None
    points = bounds.wireframe_points(target_spacing=1.0, max_segments_per_edge=2)
    assert len(points) >= 8
    for point in bounds.corners():
        assert point in points
    assert any(abs(point[0] - 10.0) > 0.5 and abs(point[1] - 20.0) > 0.5 for point in points)


def test_segment_intersection_fraction_returns_first_entry_point():
    bounds = build_oriented_bounds(
        _display_bounds(), position=(4.0, 0.0, 0.0), orientation=0.0, scale=1.0
    )
    assert bounds is not None
    fraction = bounds.segment_intersection_fraction((0.0, 0.0, 1.0), (8.0, 0.0, 1.0))
    assert fraction is not None
    assert fraction == 0.375


def test_normal_gameobject_with_bounds_registers(monkeypatch):
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.gameobject_collision.load_display_bounds",
        lambda: {56: _display_bounds()},
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_debug_enabled",
        lambda: False,
    )
    assert build_gameobject_collision_index({1: [_entry()]}) == 1


def test_collision_consumes_runtime_identity_and_transform():
    mapping = _entry(
        x=4.0,
        y=5.0,
        z=6.0,
        orientation=0.0,
        size=1.0,
        name="Persistent model metadata",
    )
    runtime_object = GameObject.from_mapping(
        {
            **mapping,
            "x": 40.0,
            "y": 50.0,
            "z": 60.0,
            "orientation": math.pi / 2.0,
            "rotation0": 0.1,
            "rotation1": 0.2,
            "rotation2": 0.3,
            "rotation3": 0.9,
            "size": 2.0,
        },
        runtime_guid=0xF11000000000000C,
    )

    collision = build_gameobject_collision(
        mapping,
        _display_bounds(),
        runtime_object,
    )

    assert collision is not None
    assert collision.guid == runtime_object.spawn_id
    assert collision.runtime_guid == runtime_object.runtime_guid
    assert collision.rotation == runtime_object.rotation
    assert collision.name == mapping["name"]
    assert collision.bounds.center == (40.0, 50.0, 62.0)
    assert collision.bounds.half_extents == (2.0, 1.0, 2.0)


def test_collision_index_reuses_long_lived_runtime_transform(monkeypatch):
    mapping = _entry(x=4.0, y=5.0, z=6.0, orientation=0.0, size=1.0)
    runtime_object = GameObject.from_mapping(
        mapping,
        runtime_guid=0xF11000000000000C,
    )
    runtime_object.set_position(40.0, 50.0, 60.0)
    runtime_object.set_orientation(math.pi / 2.0)
    runtime_object.set_scale(2.0)
    store = get_gameobject_runtime_store()
    store.clear()
    store.add(runtime_object)
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.gameobject_collision.load_display_bounds",
        lambda: {56: _display_bounds()},
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_debug_enabled",
        lambda: False,
    )
    try:
        assert build_gameobject_collision_index({1: [mapping]}) == 1
        collision = gameobject_collision_index.get(1, mapping["guid"])
    finally:
        store.clear()
        gameobject_collision_index.clear()

    assert collision is not None
    assert collision.runtime_guid == runtime_object.runtime_guid
    assert collision.bounds.center == (40.0, 50.0, 62.0)
    assert collision.bounds.half_extents == (2.0, 1.0, 2.0)


def test_transport_and_chair_types_are_excluded():
    for go_type in (7, 11, 15):
        assert not gameobject_is_eligible(_entry(type=go_type), _display_bounds())


def test_large_severed_head_button_is_eligible_but_regular_button_is_not():
    trophy_bounds = DisplayBounds((-4.5, -5.9, 0.0), (8.3, 6.8, 25.9))
    assert gameobject_is_eligible(
        _entry(type=1, size=1.25, name="The Severed Head of Nefarian"),
        trophy_bounds,
    )
    assert not gameobject_is_eligible(
        _entry(type=1, size=1.0, name="Lever"),
        _display_bounds(),
    )


def test_missing_bounds_and_decorative_sign_are_excluded():
    assert not gameobject_is_eligible(_entry(), None)
    assert not gameobject_is_eligible(_entry(type=5, name="Small wooden sign"), _display_bounds())


def test_movement_index_blocks_segment_into_solid_and_accepts_outside():
    bounds = build_oriented_bounds(
        _display_bounds(), position=(4.0, 0.0, 0.0), orientation=0.0, scale=1.0
    )
    assert bounds is not None
    index = GameObjectCollisionIndex()
    index.register(GameObjectCollision(1, 12, 34, 56, bounds))
    assert index.blocked(1, (0.0, 0.0, 1.0), (4.0, 0.0, 1.0)) is not None
    assert index.blocked(1, (0.0, 3.0, 1.0), (8.0, 3.0, 1.0)) is None


def test_start_inside_allows_escape_but_blocks_deeper_inside_traversal():
    bounds = build_oriented_bounds(
        _display_bounds(), position=(4.0, 0.0, 0.0), orientation=0.0, scale=1.0
    )
    assert bounds is not None
    index = GameObjectCollisionIndex()
    index.register(GameObjectCollision(1, 12, 34, 56, bounds))

    assert index.blocked(1, (4.0, 0.0, 1.0), (6.5, 0.0, 1.0)) is None
    assert index.blocked(1, (4.8, 0.0, 1.0), (4.8, 0.2, 1.0)) is not None
    assert index.blocked(1, (4.8, 0.0, 1.0), (4.0, 0.0, 1.0)) is not None


def test_nearby_point_returns_indexed_objects_from_same_grid_space():
    bounds = build_oriented_bounds(
        _display_bounds(), position=(32.0, 32.0, 0.0), orientation=0.0, scale=1.0
    )
    assert bounds is not None
    index = GameObjectCollisionIndex()
    index.register(GameObjectCollision(1, 12, 34, 56, bounds))
    nearby = list(index.nearby_point(1, (32.0, 32.0, 0.0), radius=5.0))
    far = list(index.nearby_point(1, (80.0, 80.0, 0.0), radius=5.0))
    assert [collision.guid for collision in nearby] == [12]
    assert far == []


def test_movement_acceptance_rejects_solid_gameobject(monkeypatch):
    gameobject_collision_index.clear()
    bounds = build_oriented_bounds(
        _display_bounds(), position=(4.0, 0.0, 0.0), orientation=0.0, scale=1.0
    )
    assert bounds is not None
    gameobject_collision_index.register(GameObjectCollision(1, 12, 34, 56, bounds))
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_enabled", lambda: True
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_debug_enabled", lambda: False
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_mode", lambda: "legacy"
    )
    session = SimpleNamespace(x=1.0, y=0.0, z=1.0, map_id=1, char_guid=99)
    assert not movement._accept_movement_update(session, "MSG_MOVE_HEARTBEAT", 4.0, 0.0, 1.0, 0.0)
    assert session._last_collision_correction is not None
    assert session._last_collision_correction[0] > 2.9
    assert session._last_collision_correction[0] < 3.05
    assert movement._accept_movement_update(session, "MSG_MOVE_HEARTBEAT", 2.0, 2.0, 1.0, 0.0)


def test_disabled_config_bypasses_collision(monkeypatch):
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_enabled", lambda: False
    )
    session = SimpleNamespace(x=1.0, y=0.0, z=1.0, map_id=1, char_guid=99)
    assert movement._accept_movement_update(session, "MSG_MOVE_HEARTBEAT", 4.0, 0.0, 1.0, 0.0)


def test_movement_handler_sends_snapback_when_gameobject_collision_rejects(monkeypatch):
    gameobject_collision_index.clear()
    bounds = build_oriented_bounds(
        _display_bounds(), position=(4.0, 0.0, 0.0), orientation=0.0, scale=1.0
    )
    assert bounds is not None
    gameobject_collision_index.register(GameObjectCollision(1, 12, 34, 56, bounds))

    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_enabled", lambda: True
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.gameobject_collision_debug_enabled", lambda: False
    )
    monkeypatch.setattr(
        movement,
        "parse_movement_info",
        lambda *args, **kwargs: (4.0, 0.0, 1.0, 0.0),
    )
    monkeypatch.setattr(
        movement,
        "_build_collision_reject_responses",
        lambda session, opcode_name: [("SMSG_MOVE_TELEPORT", b"teleport")],
    )

    session = SimpleNamespace(
        x=1.0,
        y=0.0,
        z=1.0,
        orientation=0.0,
        map_id=1,
        char_guid=99,
        movement_state=SimpleNamespace(flags=0, counter=0),
    )
    ctx = SimpleNamespace(name="MSG_MOVE_HEARTBEAT", opcode=0x01, payload=b"", decoded={})
    code, responses = movement.handle_movement_packet(session, ctx)
    assert code == 0
    assert responses == [("SMSG_MOVE_TELEPORT", b"teleport")]


def test_collision_reject_resync_uses_player_move_without_teleport_pending(monkeypatch):
    session = SimpleNamespace(
        x=1.0,
        y=2.0,
        z=3.0,
        orientation=4.0,
        char_guid=99,
        world_guid=0x0000000700000063,
        player_guid=0x0000000700000063,
        teleport_pending=True,
        worldport_ack_pending=True,
        near_teleport_pending=True,
        teleport_destination="collision-reject:MSG_MOVE_HEARTBEAT",
        movement_state=SimpleNamespace(
            counter=12,
            x=1.0,
            y=2.0,
            z=3.0,
            orientation=4.0,
            flags=(
                movement._MOVEMENTFLAG_FORWARD
                | movement._MOVEMENTFLAG_STRAFE_LEFT
                | movement._MOVEMENTFLAG_TURN_RIGHT
            ),
            flags2=movement._MOVEMENTFLAG2_CIRCLE_RUN_SYNC,
            is_ascending=False,
            is_descending=False,
        ),
        _last_movement_rejection="gameobject_collision",
        _last_collision_attempt=(9.0, 8.0, 7.0, 6.0),
        _last_collision_correction=(3.5, 2.5, 3.0, 1.25),
        _last_collision_flags_in=(
            movement._MOVEMENTFLAG_FORWARD
            | movement._MOVEMENTFLAG_STRAFE_LEFT
            | movement._MOVEMENTFLAG_TURN_RIGHT,
            movement._MOVEMENTFLAG2_CIRCLE_RUN_SYNC,
        ),
    )

    monkeypatch.setattr(
        movement,
        "build_same_map_teleport_self_resync_responses",
        lambda target: [("SMSG_UPDATE_OBJECT", b"0006")],
    )
    monkeypatch.setattr(
        movement,
        "resync_movement",
        lambda target: [("SMSG_PLAYER_MOVE", b"move")],
    )

    responses = movement._build_collision_reject_responses(session, "MSG_MOVE_HEARTBEAT")

    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"0006"),
        ("SMSG_PLAYER_MOVE", b"move"),
    ]
    assert (session.x, session.y, session.z, session.orientation) == (3.5, 2.5, 3.0, 1.25)
    assert session.movement_state.flags == 0
    assert session.movement_state.flags2 == 0
    assert session.teleport_pending is False
    assert session.worldport_ack_pending is False
    assert session.near_teleport_pending is False
    assert session.teleport_destination is None


def test_collision_reject_resync_does_not_duplicate_player_move(monkeypatch):
    session = SimpleNamespace(
        x=1.0,
        y=2.0,
        z=3.0,
        orientation=4.0,
        char_guid=99,
        world_guid=0x0000000700000063,
        player_guid=0x0000000700000063,
        teleport_pending=False,
        worldport_ack_pending=False,
        near_teleport_pending=False,
        teleport_destination=None,
        movement_state=SimpleNamespace(
            counter=12,
            x=1.0,
            y=2.0,
            z=3.0,
            orientation=4.0,
            flags=movement._MOVEMENTFLAG_FORWARD,
            flags2=movement._MOVEMENTFLAG2_CIRCLE_RUN_SYNC,
            is_ascending=False,
            is_descending=False,
        ),
        _last_movement_rejection="gameobject_collision",
        _last_collision_attempt=(9.0, 8.0, 7.0, 6.0),
        _last_collision_correction=(3.5, 2.5, 3.0, 1.25),
    )

    monkeypatch.setattr(
        movement,
        "build_same_map_teleport_self_resync_responses",
        lambda target: [("SMSG_UPDATE_OBJECT", b"0006"), ("SMSG_PLAYER_MOVE", b"move")],
    )
    monkeypatch.setattr(
        movement,
        "resync_movement",
        lambda target: [("SMSG_PLAYER_MOVE", b"duplicate")],
    )

    responses = movement._build_collision_reject_responses(session, "MSG_MOVE_HEARTBEAT")

    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"0006"),
        ("SMSG_PLAYER_MOVE", b"move"),
    ]


def test_collision_reject_sanitizes_directional_flags_but_preserves_falling(monkeypatch):
    session = SimpleNamespace(
        x=1.0,
        y=2.0,
        z=3.0,
        orientation=4.0,
        char_guid=99,
        world_guid=0x0000000700000063,
        player_guid=0x0000000700000063,
        teleport_pending=False,
        worldport_ack_pending=False,
        near_teleport_pending=False,
        teleport_destination=None,
        movement_state=SimpleNamespace(
            counter=12,
            x=1.0,
            y=2.0,
            z=3.0,
            orientation=4.0,
            flags=(
                movement._MOVEMENTFLAG_FORWARD
                | movement._MOVEMENTFLAG_STRAFE_RIGHT
                | movement._MOVEMENTFLAG_TURN_LEFT
                | movement._MOVEMENTFLAG_FALLING
            ),
            flags2=movement._MOVEMENTFLAG2_CIRCLE_RUN_SYNC,
            is_ascending=False,
            is_descending=False,
        ),
        _last_movement_rejection="gameobject_collision",
        _last_collision_attempt=(9.0, 8.0, 7.0, 6.0),
        _last_collision_correction=(3.5, 2.5, 3.0, 1.25),
        _last_collision_flags_in=(
            movement._MOVEMENTFLAG_FORWARD
            | movement._MOVEMENTFLAG_STRAFE_RIGHT
            | movement._MOVEMENTFLAG_TURN_LEFT
            | movement._MOVEMENTFLAG_FALLING,
            movement._MOVEMENTFLAG2_CIRCLE_RUN_SYNC,
        ),
    )

    monkeypatch.setattr(
        movement,
        "build_same_map_teleport_self_resync_responses",
        lambda target: [("SMSG_UPDATE_OBJECT", b"0006")],
    )
    monkeypatch.setattr(
        movement,
        "resync_movement",
        lambda target: [("SMSG_PLAYER_MOVE", b"move")],
    )

    movement._build_collision_reject_responses(session, "MSG_MOVE_HEARTBEAT")

    assert session.movement_state.flags & movement._MOVEMENTFLAG_FALLING
    assert not session.movement_state.flags & movement._MOVEMENTFLAG_FORWARD
    assert not session.movement_state.flags & movement._MOVEMENTFLAG_STRAFE_RIGHT
    assert not session.movement_state.flags & movement._MOVEMENTFLAG_TURN_LEFT
    assert session.movement_state.flags2 == 0
