from __future__ import annotations

import math
from pathlib import Path
import random

import pytest

from server.modules.handlers.world.collision.geometry import (
    BVHNode,
    DEFAULT_CONTACT_EPSILON,
    GeometryHit,
    GeometryProvider,
    GeometryQuery,
    MeshAccelerator,
    MeshBVH,
    MovementResult,
    Transform,
    TriangleMesh,
    Vec3,
    WorldGeometryMap,
    WorldMeshInstance,
    intersect_segment_aabb,
    intersect_segment_triangle,
    load_obj_mesh,
    load_obj_mesh_from_text,
    resolve_segment,
)

WALL_OBJ = """
v 0 0 0
v 0 2 0
v 0 0 2
f 1 2 3
"""

BOX_OBJ = """
v 0 0 0
v 1 0 0
v 1 1 0
v 0 1 0
v 0 0 1
v 1 0 1
v 1 1 1
v 0 1 1
f 1 2 3 4
f 5 8 7 6
f 1 5 6 2
f 2 6 7 3
f 3 7 8 4
f 4 8 5 1
"""

CORNER_OBJ = """
v 0 0 0
v 0 2 0
v 0 0 2
f 1 2 3
v 0 0 0
v 2 0 0
v 0 0 2
f 4 5 6
"""

CORRIDOR_OBJ = """
v 0 0 0
v 0 3 0
v 0 0 2
f 1 2 3
v 2 0 0
v 2 0 2
v 2 3 0
f 4 5 6
"""

RAMP_OBJ = """
v 0 0 0
v 2 0 1
v 0 2 0
f 1 2 3
"""

STAIRS_OBJ = """
v 0 0 0
v 1 0 0
v 1 1 0
v 0 1 0
f 1 2 3 4
v 1 0 0
v 2 0 1
v 2 1 1
v 1 1 0
f 5 6 7 8
"""


def _triangle():
    return (
        Vec3(0.0, 0.0, 0.0),
        Vec3(1.0, 0.0, 0.0),
        Vec3(0.0, 1.0, 0.0),
    )


def test_segment_hits_triangle():
    a, b, c = _triangle()
    hit = intersect_segment_triangle(Vec3(0.25, 0.25, 1.0), Vec3(0.25, 0.25, -1.0), a, b, c)
    assert hit is not None
    assert math.isclose(hit.fraction, 0.5, abs_tol=1e-6)
    assert hit.position == Vec3(0.25, 0.25, 0.0)
    assert hit.normal == Vec3(0.0, 0.0, 1.0)
    _assert_hit_invariants(hit, Vec3(0.25, 0.25, 1.0), Vec3(0.25, 0.25, -1.0))


def test_obj_loader_loads_three_vertices_and_one_triangle():
    mesh = load_obj_mesh_from_text(
        """
        v 0 0 0
        v 1 0 0
        v 0 1 0
        f 1 2 3
        """,
        name="tri",
    )

    assert mesh.name == "tri"
    assert len(mesh.vertices) == 3
    assert mesh.triangles == ((0, 1, 2),)


def test_obj_loader_triangulates_quad():
    mesh = load_obj_mesh_from_text(
        """
        v 0 0 0
        v 1 0 0
        v 1 1 0
        v 0 1 0
        f 1 2 3 4
        """
    )

    assert mesh.triangles == ((0, 1, 2), (0, 2, 3))


def test_obj_loader_ignores_comments_and_blank_lines():
    mesh = load_obj_mesh_from_text(
        """
        # comment

        v 0 0 0
        v 1 0 0
        v 0 1 0

        # another
        f 1 2 3
        """
    )

    assert len(mesh.vertices) == 3
    assert len(mesh.triangles) == 1


def test_obj_loader_accepts_face_forms_with_texture_and_normal_indices():
    mesh = load_obj_mesh_from_text(
        """
        v 0 0 0
        v 1 0 0
        v 0 1 0
        v 0 0 1
        f 1/1 2/2 3/3
        f 1//1 2//2 4//4
        f 1/1/1 3/3/3 4/4/4
        """
    )

    assert mesh.triangles == ((0, 1, 2), (0, 1, 3), (0, 2, 3))


def test_obj_loader_invalid_face_with_too_few_vertices():
    with pytest.raises(ValueError, match="triangles and quads"):
        load_obj_mesh_from_text(
            """
            v 0 0 0
            v 1 0 0
            f 1 2
            """
        )


def test_obj_loader_invalid_vertex_line():
    with pytest.raises(ValueError, match="vertex line"):
        load_obj_mesh_from_text(
            """
            v 0 0
            """
        )


def test_obj_loader_computes_local_aabb_after_load():
    mesh = load_obj_mesh_from_text(
        """
        v -1 2 3
        v 4 -5 6
        v 0 1 -2
        f 1 2 3
        """
    )

    assert mesh.aabb_min == Vec3(-1.0, -5.0, -2.0)
    assert mesh.aabb_max == Vec3(4.0, 2.0, 6.0)


def test_obj_loader_loaded_mesh_works_with_mesh_accelerator():
    mesh = load_obj_mesh_from_text(
        """
        v 0 0 0
        v 1 0 0
        v 0 1 0
        f 1 2 3
        """
    )
    accelerator = MeshAccelerator(mesh)

    hit = accelerator.raycast_segment(Vec3(0.2, 0.2, 1.0), Vec3(0.2, 0.2, -1.0))

    assert hit is not None
    assert hit.mesh is mesh


def test_obj_loader_loaded_mesh_works_inside_world_mesh_instance():
    mesh = load_obj_mesh_from_text(
        """
        v 0 0 0
        v 1 0 0
        v 0 1 0
        f 1 2 3
        """
    )
    instance = WorldMeshInstance(provider=mesh, transform=Transform(translation=Vec3(5.0, 0.0, 0.0)))

    hit = instance.raycast_segment(Vec3(5.2, 0.2, 1.0), Vec3(5.2, 0.2, -1.0))

    assert hit is not None
    assert hit.mesh is mesh
    assert hit.instance is instance


def test_obj_loader_loaded_mesh_works_inside_world_geometry_map():
    mesh = load_obj_mesh_from_text(
        """
        v 0 0 0
        v 1 0 0
        v 0 1 0
        f 1 2 3
        """
    )
    instance = WorldMeshInstance(provider=MeshAccelerator(mesh), transform=Transform(translation=Vec3(7.0, 0.0, 0.0)))
    world = WorldGeometryMap([instance])

    hit = world.raycast(Vec3(7.2, 0.2, 1.0), Vec3(7.2, 0.2, -1.0))

    assert hit is not None
    assert hit.mesh is mesh
    assert hit.instance is instance


def test_obj_loader_can_load_from_path(tmp_path: Path):
    path = tmp_path / "simple.obj"
    path.write_text(
        "\n".join(
            [
                "v 0 0 0",
                "v 1 0 0",
                "v 0 1 0",
                "f 1 2 3",
            ]
        ),
        encoding="utf-8",
    )

    mesh = load_obj_mesh(str(path))

    assert mesh.name == "simple"
    assert mesh.triangles == ((0, 1, 2),)


def test_resolve_segment_no_collision():
    world = WorldGeometryMap()
    start = Vec3(-1.0, 0.0, 0.0)
    end = Vec3(1.0, 0.0, 0.0)

    result = resolve_segment(start, end, world)

    assert isinstance(result, MovementResult)
    assert result.hit is None
    assert result.fraction == 1.0
    assert result.resolved_end == end
    assert result.remaining_distance == 0.0
    assert result.remaining_vector == Vec3(0.0, 0.0, 0.0)
    _assert_movement_result_invariants(result)


def test_resolve_segment_direct_wall_hit():
    world = _wall_world()
    start = Vec3(-1.0, 0.5, 0.5)
    end = Vec3(1.0, 0.5, 0.5)

    result = resolve_segment(start, end, world)

    assert result.hit is not None
    assert math.isclose(result.fraction, 0.5, abs_tol=1e-6)
    assert result.hit_position == Vec3(0.0, 0.5, 0.5)
    assert result.hit_normal is not None
    assert math.isclose(result.resolved_end.x, DEFAULT_CONTACT_EPSILON, abs_tol=1e-6)
    assert math.isclose(result.resolved_end.y, 0.5, abs_tol=1e-6)
    assert math.isclose(result.resolved_end.z, 0.5, abs_tol=1e-6)
    _assert_movement_result_invariants(result)


def test_resolve_segment_grazing_hit():
    world = _wall_world()
    start = Vec3(-1.0, 1.0, 0.5)
    end = Vec3(1.0, 1.0, 0.5)

    result = resolve_segment(start, end, world)

    assert result.hit is not None
    assert result.hit_position == Vec3(0.0, 1.0, 0.5)
    _assert_movement_result_invariants(result)


def test_resolve_segment_start_exactly_on_surface():
    world = _wall_world()
    start = Vec3(0.0, 0.5, 0.5)
    end = Vec3(1.0, 0.5, 0.5)

    result = resolve_segment(start, end, world)

    assert result.hit is not None
    assert math.isclose(result.fraction, 0.0, abs_tol=1e-6)
    assert result.resolved_end == start + (result.hit_normal * DEFAULT_CONTACT_EPSILON)
    assert result.resolved_end != result.hit_position
    _assert_movement_result_invariants(result)


def test_resolve_segment_ending_exactly_on_surface():
    world = _wall_world()
    start = Vec3(-1.0, 0.5, 0.5)
    end = Vec3(0.0, 0.5, 0.5)

    result = resolve_segment(start, end, world)

    assert result.hit is not None
    assert math.isclose(result.fraction, 1.0, abs_tol=1e-6)
    assert math.isclose(result.resolved_end.x, DEFAULT_CONTACT_EPSILON, abs_tol=1e-6)
    assert math.isclose(result.resolved_end.y, 0.5, abs_tol=1e-6)
    _assert_movement_result_invariants(result)


def test_resolve_segment_completely_before_wall():
    world = _wall_world()
    start = Vec3(-2.0, 0.5, 0.5)
    end = Vec3(-1.0, 0.5, 0.5)

    result = resolve_segment(start, end, world)

    assert result.hit is None
    assert result.resolved_end == end
    _assert_movement_result_invariants(result)


def test_resolve_segment_completely_beyond_wall():
    world = _wall_world()
    start = Vec3(1.0, 0.5, 0.5)
    end = Vec3(2.0, 0.5, 0.5)

    result = resolve_segment(start, end, world)

    assert result.hit is None
    assert result.resolved_end == end
    _assert_movement_result_invariants(result)


def test_resolve_segment_epsilon_behaves_consistently():
    world = _wall_world()
    start = Vec3(-2.0, 0.5, 0.5)
    end = Vec3(2.0, 0.5, 0.5)

    result = resolve_segment(start, end, world, contact_epsilon=0.25)

    assert result.hit is not None
    assert math.isclose(result.hit_position.x, 0.0, abs_tol=1e-6)
    assert math.isclose(result.resolved_end.x, 0.25, abs_tol=1e-6)
    assert math.isclose(result.remaining_vector.x, 1.75, abs_tol=1e-6)
    _assert_movement_result_invariants(result)


def test_resolve_segment_parallel_movement_along_wall_does_not_hit():
    world = _wall_world()
    start = Vec3(-1.0, 0.25, 0.25)
    end = Vec3(-1.0, 1.75, 0.25)

    result = resolve_segment(start, end, world)

    assert result.hit is None
    assert result.resolved_end == end
    _assert_movement_result_invariants(result)


def test_resolve_segment_zero_length_movement():
    world = _wall_world()
    start = Vec3(-1.0, 0.5, 0.5)

    result = resolve_segment(start, start, world)

    assert result.hit is None
    assert result.resolved_end == start
    _assert_movement_result_invariants(result)


def test_resolve_segment_fraction_zero_separates_and_next_zero_length_stays_off_surface():
    world = _wall_world()
    surface = Vec3(0.0, 0.5, 0.5)

    first = resolve_segment(surface, Vec3(1.0, 0.5, 0.5), world, contact_epsilon=0.05)

    assert first.hit is not None
    assert first.fraction == 0.0
    assert first.hit_position == surface
    assert first.resolved_end == Vec3(0.05, 0.5, 0.5)
    assert math.isclose((first.resolved_end - first.hit_position).length(), 0.05, abs_tol=1e-9)

    second = resolve_segment(first.resolved_end, first.resolved_end, world, contact_epsilon=0.05)
    assert second.hit is None
    assert second.resolved_end == first.resolved_end
    assert second.resolved_end != surface


def test_resolve_segment_extremely_short_movement():
    world = _wall_world()
    start = Vec3(-1e-9, 0.5, 0.5)
    end = Vec3(1e-9, 0.5, 0.5)

    result = resolve_segment(start, end, world)

    _assert_movement_result_invariants(result)


def test_resolve_segment_extremely_long_movement():
    world = _wall_world()
    start = Vec3(-1e6, 0.5, 0.5)
    end = Vec3(1e6, 0.5, 0.5)

    result = resolve_segment(start, end, world)

    assert result.hit is not None
    assert math.isclose(result.hit_position.x, 0.0, abs_tol=1e-6)
    _assert_movement_result_invariants(result)


def test_resolve_segment_diagonal_movement_into_wall():
    world = _wall_world()
    start = Vec3(-1.0, 0.25, 0.25)
    end = Vec3(1.0, 1.25, 1.25)

    result = resolve_segment(start, end, world)

    assert result.hit is not None
    assert math.isclose(result.hit_position.x, 0.0, abs_tol=1e-6)
    _assert_movement_result_invariants(result)


def test_resolve_segment_collision_against_translated_mesh():
    mesh = load_obj_mesh_from_text(WALL_OBJ, name="wall")
    world = WorldGeometryMap(
        [WorldMeshInstance(provider=MeshAccelerator(mesh), transform=Transform(translation=Vec3(5.0, 0.0, 0.0)))]
    )

    result = resolve_segment(Vec3(4.0, 0.5, 0.5), Vec3(6.0, 0.5, 0.5), world)

    assert result.hit is not None
    assert math.isclose(result.hit_position.x, 5.0, abs_tol=1e-6)
    _assert_movement_result_invariants(result)


def test_resolve_segment_collision_against_rotated_mesh():
    mesh = load_obj_mesh_from_text(WALL_OBJ, name="wall")
    world = WorldGeometryMap(
        [WorldMeshInstance(provider=MeshAccelerator(mesh), transform=Transform(rotation_yaw=math.pi / 2.0))]
    )

    result = resolve_segment(Vec3(-0.5, -1.0, 0.5), Vec3(-0.5, 1.0, 0.5), world)

    assert result.hit is not None
    assert math.isclose(result.hit_position.y, 0.0, abs_tol=1e-6)
    _assert_movement_result_invariants(result)


def test_resolve_segment_collision_against_scaled_mesh():
    mesh = load_obj_mesh_from_text(WALL_OBJ, name="wall")
    world = WorldGeometryMap([WorldMeshInstance(provider=MeshAccelerator(mesh), transform=Transform(scale=2.0))])

    result = resolve_segment(Vec3(-1.0, 1.0, 1.0), Vec3(1.0, 1.0, 1.0), world)

    assert result.hit is not None
    assert math.isclose(result.hit_position.x, 0.0, abs_tol=1e-6)
    _assert_movement_result_invariants(result)


def test_segment_misses_triangle():
    a, b, c = _triangle()
    hit = intersect_segment_triangle(Vec3(1.25, 1.25, 1.0), Vec3(1.25, 1.25, -1.0), a, b, c)
    assert hit is None


def test_segment_parallel_to_triangle_misses():
    a, b, c = _triangle()
    hit = intersect_segment_triangle(Vec3(0.25, 0.25, 1.0), Vec3(0.75, 0.25, 1.0), a, b, c)
    assert hit is None


def test_segment_almost_parallel_to_triangle_is_numerically_stable():
    a, b, c = _triangle()
    hit = intersect_segment_triangle(Vec3(0.25, 0.25, 1e-9), Vec3(0.75, 0.25, 2e-9), a, b, c)
    assert hit is None


def test_segment_crossing_triangle_full_span_hits():
    a, b, c = _triangle()
    hit = intersect_segment_triangle(Vec3(0.1, 0.1, 2.0), Vec3(0.1, 0.1, -2.0), a, b, c)
    assert hit is not None
    assert math.isclose(hit.position.z, 0.0, abs_tol=1e-6)
    _assert_hit_invariants(hit, Vec3(0.1, 0.1, 2.0), Vec3(0.1, 0.1, -2.0))


def test_segment_touching_triangle_edge_is_stable():
    a, b, c = _triangle()
    hit = intersect_segment_triangle(Vec3(0.5, 0.0, 1.0), Vec3(0.5, 0.0, -1.0), a, b, c)
    assert hit is not None
    assert hit.position == Vec3(0.5, 0.0, 0.0)
    _assert_hit_invariants(hit, Vec3(0.5, 0.0, 1.0), Vec3(0.5, 0.0, -1.0))


def test_segment_touching_triangle_vertex_is_stable():
    a, b, c = _triangle()
    hit = intersect_segment_triangle(Vec3(0.0, 0.0, 1.0), Vec3(0.0, 0.0, -1.0), a, b, c)
    assert hit is not None
    assert hit.position == Vec3(0.0, 0.0, 0.0)
    _assert_hit_invariants(hit, Vec3(0.0, 0.0, 1.0), Vec3(0.0, 0.0, -1.0))


def test_segment_hits_tiny_triangle():
    a = Vec3(0.0, 0.0, 0.0)
    b = Vec3(1e-9, 0.0, 0.0)
    c = Vec3(0.0, 1e-9, 0.0)
    hit = intersect_segment_triangle(Vec3(1e-10, 1e-10, 1.0), Vec3(1e-10, 1e-10, -1.0), a, b, c)
    assert hit is not None
    _assert_hit_invariants(hit, Vec3(1e-10, 1e-10, 1.0), Vec3(1e-10, 1e-10, -1.0))


def test_segment_hits_triangle_at_large_coordinates():
    a = Vec3(1e6, 1e6, 0.0)
    b = Vec3(1e6 + 1.0, 1e6, 0.0)
    c = Vec3(1e6, 1e6 + 1.0, 0.0)
    start = Vec3(1e6 + 0.25, 1e6 + 0.25, 1.0)
    end = Vec3(1e6 + 0.25, 1e6 + 0.25, -1.0)
    hit = intersect_segment_triangle(start, end, a, b, c)
    assert hit is not None
    _assert_hit_invariants(hit, start, end)


def test_segment_hits_triangle_at_small_coordinates():
    a = Vec3(0.0, 0.0, 0.0)
    b = Vec3(1e-6, 0.0, 0.0)
    c = Vec3(0.0, 1e-6, 0.0)
    start = Vec3(2e-7, 2e-7, 1.0)
    end = Vec3(2e-7, 2e-7, -1.0)
    hit = intersect_segment_triangle(start, end, a, b, c)
    assert hit is not None
    _assert_hit_invariants(hit, start, end)


def test_segment_hits_aabb():
    hit = intersect_segment_aabb(
        Vec3(-1.0, 0.5, 0.5),
        Vec3(2.0, 0.5, 0.5),
        Vec3(0.0, 0.0, 0.0),
        Vec3(1.0, 1.0, 1.0),
    )
    assert hit is not None
    assert math.isclose(hit.entry_fraction, 1.0 / 3.0, abs_tol=1e-6)
    assert math.isclose(hit.exit_fraction, 2.0 / 3.0, abs_tol=1e-6)


def test_segment_misses_aabb():
    hit = intersect_segment_aabb(
        Vec3(-1.0, 2.0, 0.5),
        Vec3(2.0, 2.0, 0.5),
        Vec3(0.0, 0.0, 0.0),
        Vec3(1.0, 1.0, 1.0),
    )
    assert hit is None


def test_nearest_triangle_hit_is_selected():
    mesh = TriangleMesh.from_vertices(
        [
            Vec3(0.0, 0.0, 0.0),
            Vec3(1.0, 0.0, 0.0),
            Vec3(0.0, 1.0, 0.0),
            Vec3(0.0, 0.0, -1.0),
            Vec3(1.0, 0.0, -1.0),
            Vec3(0.0, 1.0, -1.0),
        ],
        [(0, 1, 2), (3, 4, 5)],
    )
    hit = mesh.raycast_segment(Vec3(0.2, 0.2, 1.0), Vec3(0.2, 0.2, -2.0))
    assert hit is not None
    assert hit.triangle_index == 0
    assert math.isclose(hit.position.z, 0.0, abs_tol=1e-6)


def test_hit_normal_direction_is_stable():
    mesh = TriangleMesh.from_vertices(
        [Vec3(0.0, 0.0, 0.0), Vec3(1.0, 0.0, 0.0), Vec3(0.0, 1.0, 0.0)],
        [(0, 1, 2)],
    )
    hit = mesh.raycast_segment(Vec3(0.2, 0.2, 1.0), Vec3(0.2, 0.2, -1.0))
    assert hit is not None
    assert hit.normal == Vec3(0.0, 0.0, 1.0)
    assert math.isclose(hit.distance, 1.0, abs_tol=1e-6)
    _assert_hit_invariants(hit, Vec3(0.2, 0.2, 1.0), Vec3(0.2, 0.2, -1.0))


def test_vec3_normalize_zero_vector_is_finite():
    normalized = Vec3(0.0, 0.0, 0.0).normalize()
    assert normalized == Vec3(0.0, 0.0, 0.0)
    _assert_vec3_finite(normalized)


def test_vec3_cross_product_orthogonality():
    a = Vec3(1.0, 0.0, 0.0)
    b = Vec3(0.0, 1.0, 0.0)
    c = a.cross(b)
    assert c == Vec3(0.0, 0.0, 1.0)
    assert math.isclose(c.dot(a), 0.0, abs_tol=1e-9)
    assert math.isclose(c.dot(b), 0.0, abs_tol=1e-9)


def test_transform_translation_only():
    transform = Transform(translation=Vec3(10.0, 20.0, 30.0))
    point = Vec3(1.0, 2.0, 3.0)
    assert transform.local_to_world_position(point) == Vec3(11.0, 22.0, 33.0)
    assert transform.world_to_local_position(Vec3(11.0, 22.0, 33.0)) == point


def test_transform_rotation_only():
    transform = Transform(rotation_yaw=math.pi / 2.0)
    point = Vec3(1.0, 0.0, 0.0)
    rotated = transform.local_to_world_position(point)
    assert math.isclose(rotated.x, 0.0, abs_tol=1e-6)
    assert math.isclose(rotated.y, 1.0, abs_tol=1e-6)
    assert math.isclose(rotated.z, 0.0, abs_tol=1e-6)
    local = transform.world_to_local_position(rotated)
    assert math.isclose(local.x, 1.0, abs_tol=1e-6)
    assert math.isclose(local.y, 0.0, abs_tol=1e-6)


def test_transform_scale_only():
    transform = Transform(scale=2.0)
    point = Vec3(1.0, 2.0, 3.0)
    assert transform.local_to_world_position(point) == Vec3(2.0, 4.0, 6.0)
    assert transform.world_to_local_position(Vec3(2.0, 4.0, 6.0)) == point


def test_transform_translation_and_rotation():
    transform = Transform(translation=Vec3(5.0, 6.0, 7.0), rotation_yaw=math.pi / 2.0)
    world = transform.local_to_world_position(Vec3(1.0, 0.0, 0.0))
    assert math.isclose(world.x, 5.0, abs_tol=1e-6)
    assert math.isclose(world.y, 7.0, abs_tol=1e-6)
    assert math.isclose(world.z, 7.0, abs_tol=1e-6)


def test_transform_translation_rotation_and_scale():
    transform = Transform(translation=Vec3(10.0, 0.0, 1.0), rotation_yaw=math.pi / 2.0, scale=2.0)
    world = transform.local_to_world_position(Vec3(1.0, 0.0, 1.0))
    assert math.isclose(world.x, 10.0, abs_tol=1e-6)
    assert math.isclose(world.y, 2.0, abs_tol=1e-6)
    assert math.isclose(world.z, 3.0, abs_tol=1e-6)
    local = transform.world_to_local_position(world)
    assert math.isclose(local.x, 1.0, abs_tol=1e-6)
    assert math.isclose(local.y, 0.0, abs_tol=1e-6)
    assert math.isclose(local.z, 1.0, abs_tol=1e-6)


def test_world_mesh_raycast_translation_only():
    mesh = TriangleMesh.from_vertices(
        [Vec3(0.0, 0.0, 0.0), Vec3(1.0, 0.0, 0.0), Vec3(0.0, 1.0, 0.0)],
        [(0, 1, 2)],
    )
    instance = WorldMeshInstance(provider=mesh, transform=Transform(translation=Vec3(10.0, 0.0, 0.0)))
    hit = instance.raycast_segment(Vec3(10.2, 0.2, 1.0), Vec3(10.2, 0.2, -1.0))
    assert hit is not None
    assert math.isclose(hit.position.x, 10.2, abs_tol=1e-6)
    assert math.isclose(hit.position.y, 0.2, abs_tol=1e-6)
    assert math.isclose(hit.position.z, 0.0, abs_tol=1e-6)
    _assert_hit_invariants(hit, Vec3(10.2, 0.2, 1.0), Vec3(10.2, 0.2, -1.0))


def test_world_mesh_raycast_rotation_only_preserves_normal():
    mesh = TriangleMesh.from_vertices(
        [Vec3(0.0, 0.0, 0.0), Vec3(1.0, 0.0, 0.0), Vec3(0.0, 1.0, 0.0)],
        [(0, 1, 2)],
    )
    instance = WorldMeshInstance(provider=mesh, transform=Transform(rotation_yaw=math.pi / 2.0))
    hit = instance.raycast_segment(Vec3(-0.2, 0.2, 1.0), Vec3(-0.2, 0.2, -1.0))
    assert hit is not None
    assert hit.normal == Vec3(0.0, 0.0, 1.0)
    _assert_hit_invariants(hit, Vec3(-0.2, 0.2, 1.0), Vec3(-0.2, 0.2, -1.0))


def test_world_mesh_raycast_scale_only_keeps_nearest_hit():
    mesh = TriangleMesh.from_vertices(
        [
            Vec3(0.0, 0.0, 0.0),
            Vec3(1.0, 0.0, 0.0),
            Vec3(0.0, 1.0, 0.0),
            Vec3(0.0, 0.0, -1.0),
            Vec3(1.0, 0.0, -1.0),
            Vec3(0.0, 1.0, -1.0),
        ],
        [(0, 1, 2), (3, 4, 5)],
    )
    instance = WorldMeshInstance(provider=mesh, transform=Transform(scale=2.0))
    hit = instance.raycast_segment(Vec3(0.4, 0.4, 2.0), Vec3(0.4, 0.4, -3.0))
    assert hit is not None
    assert hit.triangle_index == 0
    assert math.isclose(hit.position.z, 0.0, abs_tol=1e-6)
    _assert_hit_invariants(hit, Vec3(0.4, 0.4, 2.0), Vec3(0.4, 0.4, -3.0))


def test_world_mesh_raycast_translation_rotation_and_scale():
    mesh = TriangleMesh.from_vertices(
        [Vec3(0.0, 0.0, 0.0), Vec3(1.0, 0.0, 0.0), Vec3(0.0, 1.0, 0.0)],
        [(0, 1, 2)],
    )
    instance = WorldMeshInstance(
        provider=mesh,
        transform=Transform(translation=Vec3(5.0, 5.0, 1.0), rotation_yaw=math.pi / 2.0, scale=2.0),
    )
    hit = instance.raycast_segment(Vec3(4.6, 5.4, 3.0), Vec3(4.6, 5.4, -1.0))
    assert hit is not None
    assert math.isclose(hit.position.x, 4.6, abs_tol=1e-6)
    assert math.isclose(hit.position.y, 5.4, abs_tol=1e-6)
    assert math.isclose(hit.position.z, 1.0, abs_tol=1e-6)
    assert hit.mesh is mesh
    assert hit.instance is instance
    _assert_hit_invariants(hit, Vec3(4.6, 5.4, 3.0), Vec3(4.6, 5.4, -1.0))


def test_world_mesh_instance_queries_ramp_scene():
    mesh = load_obj_mesh_from_text(RAMP_OBJ, name="ramp")
    instance = WorldMeshInstance(provider=MeshAccelerator(mesh), transform=Transform())

    hit = instance.raycast_segment(Vec3(0.5, 0.5, 2.0), Vec3(0.5, 0.5, -1.0))

    assert hit is not None
    _assert_hit_invariants(hit, Vec3(0.5, 0.5, 2.0), Vec3(0.5, 0.5, -1.0))


class _StubProvider(GeometryProvider):
    def __init__(self, hit: GeometryHit | None):
        self.hit = hit
        self.calls: list[tuple[Vec3, Vec3]] = []

    def raycast_segment(self, start: Vec3, end: Vec3) -> GeometryHit | None:
        self.calls.append((start, end))
        return self.hit


def test_geometry_query_forwards_to_provider():
    expected = GeometryHit(
        fraction=0.25,
        distance=2.0,
        position=Vec3(1.0, 2.0, 3.0),
        normal=Vec3(0.0, 0.0, 1.0),
        triangle_index=7,
    )
    provider = _StubProvider(expected)
    query = GeometryQuery(provider)

    hit = query.raycast(Vec3(0.0, 0.0, 0.0), Vec3(4.0, 0.0, 0.0))

    assert hit == expected
    assert provider.calls == [(Vec3(0.0, 0.0, 0.0), Vec3(4.0, 0.0, 0.0))]


def test_geometry_hit_contains_provider_context():
    mesh = TriangleMesh.from_vertices(
        [Vec3(0.0, 0.0, 0.0), Vec3(1.0, 0.0, 0.0), Vec3(0.0, 1.0, 0.0)],
        [(0, 1, 2)],
        name="tri",
        model_id=42,
    )
    instance = WorldMeshInstance(provider=mesh, transform=Transform(), name="inst", instance_id=99)

    hit = instance.raycast_segment(Vec3(0.2, 0.2, 1.0), Vec3(0.2, 0.2, -1.0))

    assert hit is not None
    assert hit.mesh is mesh
    assert hit.instance is instance
    assert hit.triangle_index == 0


def test_triangle_mesh_provider_contract_still_works():
    mesh = TriangleMesh.from_vertices(
        [Vec3(0.0, 0.0, 0.0), Vec3(1.0, 0.0, 0.0), Vec3(0.0, 1.0, 0.0)],
        [(0, 1, 2)],
    )
    query = GeometryQuery(mesh)

    hit = query.raycast(Vec3(0.2, 0.2, 1.0), Vec3(0.2, 0.2, -1.0))

    assert hit is not None
    assert hit.mesh is mesh
    assert hit.instance is None


def test_bvh_empty_mesh_returns_no_hit():
    mesh = TriangleMesh.from_vertices([], [])
    accelerator = MeshAccelerator(mesh)

    hit = accelerator.raycast_segment(Vec3(0.0, 0.0, 0.0), Vec3(1.0, 1.0, 1.0))

    assert hit is None
    assert accelerator.bvh.root is None


def test_bvh_single_triangle_matches_bruteforce():
    mesh = TriangleMesh.from_vertices(
        [Vec3(0.0, 0.0, 0.0), Vec3(1.0, 0.0, 0.0), Vec3(0.0, 1.0, 0.0)],
        [(0, 1, 2)],
    )
    accelerator = MeshAccelerator(mesh)
    start = Vec3(0.2, 0.2, 1.0)
    end = Vec3(0.2, 0.2, -1.0)

    brute_hit = mesh.raycast_segment(start, end)
    bvh_hit = accelerator.raycast_segment(start, end)

    _assert_hits_equal(brute_hit, bvh_hit)
    _assert_hit_invariants(bvh_hit, start, end)


def test_bvh_multiple_triangles_matches_bruteforce_nearest_hit():
    mesh = TriangleMesh.from_vertices(
        [
            Vec3(0.0, 0.0, 0.0),
            Vec3(1.0, 0.0, 0.0),
            Vec3(0.0, 1.0, 0.0),
            Vec3(0.0, 0.0, -1.0),
            Vec3(1.0, 0.0, -1.0),
            Vec3(0.0, 1.0, -1.0),
            Vec3(0.0, 0.0, -2.0),
            Vec3(1.0, 0.0, -2.0),
            Vec3(0.0, 1.0, -2.0),
        ],
        [(0, 1, 2), (3, 4, 5), (6, 7, 8)],
    )
    accelerator = MeshAccelerator(mesh)
    start = Vec3(0.25, 0.25, 1.0)
    end = Vec3(0.25, 0.25, -3.0)

    brute_hit = mesh.raycast_segment(start, end)
    bvh_hit = accelerator.raycast_segment(start, end)

    _assert_hits_equal(brute_hit, bvh_hit)
    assert bvh_hit is not None
    assert bvh_hit.triangle_index == 0


def test_bvh_miss_matches_bruteforce():
    mesh = TriangleMesh.from_vertices(
        [Vec3(0.0, 0.0, 0.0), Vec3(1.0, 0.0, 0.0), Vec3(0.0, 1.0, 0.0)],
        [(0, 1, 2)],
    )
    accelerator = MeshAccelerator(mesh)
    start = Vec3(2.0, 2.0, 1.0)
    end = Vec3(2.0, 2.0, -1.0)

    _assert_hits_equal(mesh.raycast_segment(start, end), accelerator.raycast_segment(start, end))


def test_bvh_build_is_deterministic():
    mesh = TriangleMesh.from_vertices(
        [
            Vec3(0.0, 0.0, 0.0),
            Vec3(1.0, 0.0, 0.0),
            Vec3(0.0, 1.0, 0.0),
            Vec3(2.0, 0.0, 0.0),
            Vec3(3.0, 0.0, 0.0),
            Vec3(2.0, 1.0, 0.0),
            Vec3(4.0, 0.0, 0.0),
            Vec3(5.0, 0.0, 0.0),
            Vec3(4.0, 1.0, 0.0),
        ],
        [(0, 1, 2), (3, 4, 5), (6, 7, 8)],
    )

    a = MeshBVH.build(mesh, leaf_size=1)
    b = MeshBVH.build(mesh, leaf_size=1)

    assert _serialize_bvh(a.root) == _serialize_bvh(b.root)


def test_bvh_leaf_size_changes_traversal_shape_not_hit_result():
    mesh = TriangleMesh.from_vertices(
        [
            Vec3(0.0, 0.0, 0.0),
            Vec3(1.0, 0.0, 0.0),
            Vec3(0.0, 1.0, 0.0),
            Vec3(0.0, 0.0, -1.0),
            Vec3(1.0, 0.0, -1.0),
            Vec3(0.0, 1.0, -1.0),
            Vec3(0.0, 0.0, -2.0),
            Vec3(1.0, 0.0, -2.0),
            Vec3(0.0, 1.0, -2.0),
        ],
        [(0, 1, 2), (3, 4, 5), (6, 7, 8)],
    )
    start = Vec3(0.2, 0.2, 1.0)
    end = Vec3(0.2, 0.2, -3.0)

    small_leaf = MeshAccelerator(mesh, leaf_size=1)
    large_leaf = MeshAccelerator(mesh, leaf_size=8)

    _assert_hits_equal(small_leaf.raycast_segment(start, end), large_leaf.raycast_segment(start, end))


def test_geometry_query_accepts_accelerated_provider():
    mesh = TriangleMesh.from_vertices(
        [Vec3(0.0, 0.0, 0.0), Vec3(1.0, 0.0, 0.0), Vec3(0.0, 1.0, 0.0)],
        [(0, 1, 2)],
    )
    query = GeometryQuery(MeshAccelerator(mesh))

    hit = query.raycast(Vec3(0.2, 0.2, 1.0), Vec3(0.2, 0.2, -1.0))

    assert hit is not None
    assert hit.mesh is mesh
    assert hit.instance is None


def test_geometry_query_is_deterministic_over_repeated_queries():
    mesh = load_obj_mesh_from_text(BOX_OBJ, name="box")
    query = GeometryQuery(MeshAccelerator(mesh))
    start = Vec3(0.5, 0.5, 2.0)
    end = Vec3(0.5, 0.5, -1.0)

    first = query.raycast(start, end)
    for _ in range(20):
        current = query.raycast(start, end)
        _assert_hits_equal(first, current)


def test_world_geometry_map_empty_world_returns_no_hit():
    world = WorldGeometryMap()

    hit = world.raycast(Vec3(0.0, 0.0, 0.0), Vec3(1.0, 1.0, 1.0))

    assert hit is None


def test_world_geometry_map_one_instance_returns_hit():
    mesh = TriangleMesh.from_vertices(
        [Vec3(0.0, 0.0, 0.0), Vec3(1.0, 0.0, 0.0), Vec3(0.0, 1.0, 0.0)],
        [(0, 1, 2)],
    )
    instance = WorldMeshInstance(provider=mesh, transform=Transform(translation=Vec3(2.0, 0.0, 0.0)), instance_id=1)
    world = WorldGeometryMap()
    world.add_instance(instance)

    hit = world.raycast(Vec3(2.2, 0.2, 1.0), Vec3(2.2, 0.2, -1.0))

    assert hit is not None
    assert hit.instance is instance
    assert hit.mesh is mesh


def test_world_geometry_map_nearest_instance_is_selected():
    mesh = TriangleMesh.from_vertices(
        [Vec3(0.0, 0.0, 0.0), Vec3(1.0, 0.0, 0.0), Vec3(0.0, 1.0, 0.0)],
        [(0, 1, 2)],
    )
    near_instance = WorldMeshInstance(provider=mesh, transform=Transform(translation=Vec3(0.0, 0.0, 0.0)), instance_id=10)
    far_instance = WorldMeshInstance(provider=mesh, transform=Transform(translation=Vec3(0.0, 0.0, -2.0)), instance_id=20)
    world = WorldGeometryMap([far_instance, near_instance])

    hit = world.raycast(Vec3(0.2, 0.2, 1.0), Vec3(0.2, 0.2, -3.0))

    assert hit is not None
    assert hit.instance is near_instance
    assert math.isclose(hit.position.z, 0.0, abs_tol=1e-6)


def test_world_geometry_map_overlapping_instances_are_deterministic():
    mesh = TriangleMesh.from_vertices(
        [Vec3(0.0, 0.0, 0.0), Vec3(1.0, 0.0, 0.0), Vec3(0.0, 1.0, 0.0)],
        [(0, 1, 2)],
    )
    first = WorldMeshInstance(provider=mesh, transform=Transform(), instance_id=1, name="first")
    second = WorldMeshInstance(provider=mesh, transform=Transform(), instance_id=2, name="second")
    world = WorldGeometryMap([first, second])

    hit_a = world.raycast(Vec3(0.2, 0.2, 1.0), Vec3(0.2, 0.2, -1.0))
    hit_b = world.raycast(Vec3(0.2, 0.2, 1.0), Vec3(0.2, 0.2, -1.0))

    assert hit_a is not None
    assert hit_b is not None
    assert hit_a.instance is first
    assert hit_b.instance is first


def test_world_geometry_map_translated_rotated_and_scaled_instances_work():
    mesh = TriangleMesh.from_vertices(
        [Vec3(0.0, 0.0, 0.0), Vec3(1.0, 0.0, 0.0), Vec3(0.0, 1.0, 0.0)],
        [(0, 1, 2)],
    )
    translated = WorldMeshInstance(provider=mesh, transform=Transform(translation=Vec3(10.0, 0.0, 0.0)), instance_id=1)
    rotated = WorldMeshInstance(provider=mesh, transform=Transform(rotation_yaw=math.pi / 2.0), instance_id=2)
    scaled = WorldMeshInstance(provider=mesh, transform=Transform(scale=2.0), instance_id=3)
    world = WorldGeometryMap([translated, rotated, scaled])

    translated_hit = world.raycast(Vec3(10.2, 0.2, 1.0), Vec3(10.2, 0.2, -1.0))
    rotated_hit = world.raycast(Vec3(-0.2, 0.2, 1.0), Vec3(-0.2, 0.2, -1.0))
    scaled_hit = world.raycast(Vec3(0.4, 0.4, 2.0), Vec3(0.4, 0.4, -1.0))

    assert translated_hit is not None and translated_hit.instance is translated
    assert rotated_hit is not None and rotated_hit.instance is rotated
    assert scaled_hit is not None and scaled_hit.instance is scaled


def test_world_geometry_map_remove_instance():
    mesh = TriangleMesh.from_vertices(
        [Vec3(0.0, 0.0, 0.0), Vec3(1.0, 0.0, 0.0), Vec3(0.0, 1.0, 0.0)],
        [(0, 1, 2)],
    )
    instance = WorldMeshInstance(provider=mesh, transform=Transform(), instance_id=1)
    world = WorldGeometryMap([instance])

    assert world.remove_instance(instance) is True
    assert world.remove_instance(instance) is False
    assert world.raycast(Vec3(0.2, 0.2, 1.0), Vec3(0.2, 0.2, -1.0)) is None


def test_geometry_query_accepts_world_geometry_map():
    mesh = TriangleMesh.from_vertices(
        [Vec3(0.0, 0.0, 0.0), Vec3(1.0, 0.0, 0.0), Vec3(0.0, 1.0, 0.0)],
        [(0, 1, 2)],
    )
    instance = WorldMeshInstance(provider=MeshAccelerator(mesh), transform=Transform(translation=Vec3(3.0, 0.0, 0.0)))
    query = GeometryQuery(WorldGeometryMap([instance]))

    hit = query.raycast(Vec3(3.2, 0.2, 1.0), Vec3(3.2, 0.2, -1.0))

    assert hit is not None
    assert hit.instance is instance
    assert hit.mesh is mesh


def test_world_geometry_map_randomized_regression_matches_bruteforce_world_traversal():
    randomizer = random.Random(4242)
    cube_mesh = _unit_cube_surface_mesh()

    for _ in range(10):
        instances: list[WorldMeshInstance] = []
        for instance_id in range(8):
            translation = _random_vec3(randomizer, scale=6.0)
            provider = MeshAccelerator(cube_mesh) if (instance_id % 2 == 0) else cube_mesh
            instances.append(
                WorldMeshInstance(
                    provider=provider,
                    transform=Transform(translation=translation),
                    instance_id=instance_id,
                )
            )
        world = WorldGeometryMap(list(instances))

        for _ in range(20):
            start = _random_vec3(randomizer, scale=10.0)
            end = _random_vec3(randomizer, scale=10.0)
            expected = _bruteforce_world_raycast(instances, start, end)
            actual = world.raycast(start, end)
            _assert_hits_equal(expected, actual)
            if expected is not None and actual is not None:
                assert actual.instance is expected.instance


def test_world_geometry_map_corridor_and_corner_scenes_are_deterministic():
    meshes = [
        load_obj_mesh_from_text(CORRIDOR_OBJ, name="corridor"),
        load_obj_mesh_from_text(CORNER_OBJ, name="corner"),
        load_obj_mesh_from_text(STAIRS_OBJ, name="stairs"),
    ]
    instances = [
        WorldMeshInstance(provider=MeshAccelerator(meshes[0]), transform=Transform()),
        WorldMeshInstance(provider=MeshAccelerator(meshes[1]), transform=Transform(translation=Vec3(5.0, 0.0, 0.0))),
        WorldMeshInstance(provider=MeshAccelerator(meshes[2]), transform=Transform(translation=Vec3(10.0, 0.0, 0.0))),
    ]
    world = WorldGeometryMap(instances)
    start = Vec3(1.0, 1.0, 3.0)
    end = Vec3(1.0, 1.0, -1.0)

    first = world.raycast(start, end)
    for _ in range(20):
        current = world.raycast(start, end)
        _assert_hits_equal(first, current)


def test_resolve_segment_is_deterministic_over_repeated_runs():
    world = _wall_world()
    start = Vec3(-1.0, 0.5, 0.5)
    end = Vec3(1.0, 0.5, 0.5)

    first = resolve_segment(start, end, world)
    for _ in range(20):
        current = resolve_segment(start, end, world)
        _assert_movement_results_equal(first, current)


def _unit_cube_surface_mesh() -> TriangleMesh:
    vertices = [
        Vec3(0.0, 0.0, 0.0),
        Vec3(1.0, 0.0, 0.0),
        Vec3(1.0, 1.0, 0.0),
        Vec3(0.0, 1.0, 0.0),
        Vec3(0.0, 0.0, 1.0),
        Vec3(1.0, 0.0, 1.0),
        Vec3(1.0, 1.0, 1.0),
        Vec3(0.0, 1.0, 1.0),
    ]
    triangles = [
        (0, 1, 2), (0, 2, 3),
        (4, 6, 5), (4, 7, 6),
        (0, 4, 5), (0, 5, 1),
        (1, 5, 6), (1, 6, 2),
        (2, 6, 7), (2, 7, 3),
        (3, 7, 4), (3, 4, 0),
    ]
    return TriangleMesh.from_vertices(vertices, triangles, name="unit_cube")


def _wall_world() -> WorldGeometryMap:
    mesh = load_obj_mesh_from_text(
        """
        v 0 0 0
        v 0 1 0
        v 0 1 1
        v 0 0 1
        f 1 2 3 4
        """,
        name="wall",
    )
    instance = WorldMeshInstance(provider=MeshAccelerator(mesh), transform=Transform(), instance_id=1, name="wall")
    return WorldGeometryMap([instance])


def _bruteforce_world_raycast(
    instances: list[WorldMeshInstance],
    start: Vec3,
    end: Vec3,
) -> GeometryHit | None:
    hits: list[GeometryHit] = []
    for instance in instances:
        hit = instance.raycast_segment(start, end)
        if hit is not None:
            hits.append(hit)
    if not hits:
        return None
    return min(hits, key=lambda hit: float(hit.fraction))


def test_bvh_randomized_regression_matches_bruteforce():
    randomizer = random.Random(1337)

    for _ in range(25):
        mesh = _random_mesh(randomizer, triangle_count=12)
        accelerator = MeshAccelerator(mesh, leaf_size=4)
        for _ in range(20):
            start = _random_vec3(randomizer, scale=8.0)
            end = _random_vec3(randomizer, scale=8.0)
            brute_hit = mesh.raycast_segment(start, end)
            bvh_hit = accelerator.raycast_segment(start, end)
            _assert_hits_equal(brute_hit, bvh_hit)


def test_world_mesh_randomized_regression_bruteforce_vs_bvh_with_transforms():
    randomizer = random.Random(20260707)

    for _ in range(20):
        mesh = _random_mesh(randomizer, triangle_count=16)
        transform = Transform(
            translation=_random_vec3(randomizer, scale=5.0),
            rotation_yaw=randomizer.uniform(-math.pi, math.pi),
            scale=randomizer.uniform(0.25, 3.0),
        )
        brute_instance = WorldMeshInstance(provider=mesh, transform=transform)
        bvh_instance = WorldMeshInstance(provider=MeshAccelerator(mesh), transform=transform)

        for _ in range(25):
            start = _random_vec3(randomizer, scale=10.0)
            end = _random_vec3(randomizer, scale=10.0)
            _assert_hits_equal(
                brute_instance.raycast_segment(start, end),
                bvh_instance.raycast_segment(start, end),
            )


@pytest.mark.parametrize("triangle_count", [8, 32, 128])
def test_bvh_matches_bruteforce_for_increasing_mesh_sizes(triangle_count: int):
    randomizer = random.Random(9000 + triangle_count)
    mesh = _random_mesh(randomizer, triangle_count=triangle_count)
    accelerator = MeshAccelerator(mesh, leaf_size=4)

    for _ in range(40):
        start = _random_vec3(randomizer, scale=10.0)
        end = _random_vec3(randomizer, scale=10.0)
        _assert_hits_equal(mesh.raycast_segment(start, end), accelerator.raycast_segment(start, end))


def _random_vec3(randomizer: random.Random, *, scale: float) -> Vec3:
    return Vec3(
        randomizer.uniform(-scale, scale),
        randomizer.uniform(-scale, scale),
        randomizer.uniform(-scale, scale),
    )


def _random_mesh(randomizer: random.Random, *, triangle_count: int) -> TriangleMesh:
    vertices: list[Vec3] = []
    triangles: list[tuple[int, int, int]] = []
    for _ in range(triangle_count):
        base = _random_vec3(randomizer, scale=4.0)
        v0 = base
        v1 = base + Vec3(randomizer.uniform(0.2, 1.2), randomizer.uniform(-0.8, 0.8), randomizer.uniform(-0.8, 0.8))
        v2 = base + Vec3(randomizer.uniform(-0.8, 0.8), randomizer.uniform(0.2, 1.2), randomizer.uniform(-0.8, 0.8))
        start_index = len(vertices)
        vertices.extend([v0, v1, v2])
        triangles.append((start_index, start_index + 1, start_index + 2))
    return TriangleMesh.from_vertices(vertices, triangles)


def _assert_movement_results_equal(left: MovementResult, right: MovementResult) -> None:
    _assert_hits_equal(left.hit, right.hit)
    assert math.isclose(left.fraction, right.fraction, abs_tol=1e-6)
    _assert_vec3_close(left.start, right.start)
    _assert_vec3_close(left.requested_end, right.requested_end)
    _assert_vec3_close(left.resolved_end, right.resolved_end)
    if left.hit_position is None or right.hit_position is None:
        assert left.hit_position is None and right.hit_position is None
    else:
        _assert_vec3_close(left.hit_position, right.hit_position)
    if left.hit_normal is None or right.hit_normal is None:
        assert left.hit_normal is None and right.hit_normal is None
    else:
        _assert_vec3_close(left.hit_normal, right.hit_normal)
    assert math.isclose(left.remaining_distance, right.remaining_distance, abs_tol=1e-6)
    _assert_vec3_close(left.remaining_vector, right.remaining_vector)


def _assert_movement_result_invariants(result: MovementResult) -> None:
    assert 0.0 <= float(result.fraction) <= 1.0
    _assert_vec3_finite(result.start)
    _assert_vec3_finite(result.requested_end)
    _assert_vec3_finite(result.resolved_end)
    _assert_vec3_finite(result.remaining_vector)
    assert math.isfinite(result.remaining_distance)
    assert result.remaining_distance >= 0.0
    if result.hit is None:
        assert result.hit_position is None
        assert result.hit_normal is None
    else:
        assert result.hit_position is not None
        assert result.hit_normal is not None
        _assert_hit_invariants(result.hit, result.start, result.requested_end)
        _assert_vec3_finite(result.hit_position)
        _assert_vec3_finite(result.hit_normal)
        normal_length = result.hit_normal.length()
        assert math.isclose(normal_length, 1.0, abs_tol=1e-6)


def _assert_hits_equal(left: GeometryHit | None, right: GeometryHit | None) -> None:
    assert (left is None) == (right is None)
    if left is None or right is None:
        return
    assert math.isclose(left.fraction, right.fraction, abs_tol=1e-6)
    assert math.isclose(left.distance, right.distance, abs_tol=1e-6)
    assert math.isclose(left.position.x, right.position.x, abs_tol=1e-6)
    assert math.isclose(left.position.y, right.position.y, abs_tol=1e-6)
    assert math.isclose(left.position.z, right.position.z, abs_tol=1e-6)
    assert math.isclose(left.normal.x, right.normal.x, abs_tol=1e-6)
    assert math.isclose(left.normal.y, right.normal.y, abs_tol=1e-6)
    assert math.isclose(left.normal.z, right.normal.z, abs_tol=1e-6)
    assert left.triangle_index == right.triangle_index


def _assert_hit_invariants(hit: GeometryHit | None, start: Vec3, end: Vec3) -> None:
    assert hit is not None
    assert 0.0 <= float(hit.fraction) <= 1.0
    assert math.isfinite(hit.distance)
    assert hit.distance >= 0.0
    _assert_vec3_finite(hit.position)
    _assert_vec3_finite(hit.normal)
    assert math.isclose(hit.normal.length(), 1.0, abs_tol=1e-6)
    expected = start + ((end - start) * float(hit.fraction))
    _assert_vec3_close(hit.position, expected)


def _assert_vec3_close(left: Vec3, right: Vec3, *, abs_tol: float = 1e-6) -> None:
    assert math.isclose(left.x, right.x, abs_tol=abs_tol)
    assert math.isclose(left.y, right.y, abs_tol=abs_tol)
    assert math.isclose(left.z, right.z, abs_tol=abs_tol)


def _assert_vec3_finite(vec: Vec3) -> None:
    assert math.isfinite(vec.x)
    assert math.isfinite(vec.y)
    assert math.isfinite(vec.z)


def _serialize_bvh(node: BVHNode | None) -> tuple | None:
    if node is None:
        return None
    return (
        (
            round(node.minimum.x, 6),
            round(node.minimum.y, 6),
            round(node.minimum.z, 6),
        ),
        (
            round(node.maximum.x, 6),
            round(node.maximum.y, 6),
            round(node.maximum.z, 6),
        ),
        tuple(node.triangle_indices),
        _serialize_bvh(node.left),
        _serialize_bvh(node.right),
    )
