from __future__ import annotations

from pathlib import Path

from .mesh import TriangleMesh
from .vector import Vec3


def load_obj_mesh(path: str, name: str | None = None) -> TriangleMesh:
    obj_path = Path(path)
    text = obj_path.read_text(encoding="utf-8")
    return load_obj_mesh_from_text(text, name=name or obj_path.stem)


def load_obj_mesh_from_text(text: str, name: str | None = None) -> TriangleMesh:
    vertices: list[Vec3] = []
    triangles: list[tuple[int, int, int]] = []

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        prefix = parts[0]

        if prefix == "v":
            if len(parts) != 4:
                raise ValueError(f"Invalid OBJ vertex line at {line_number}: expected 3 components")
            try:
                x = float(parts[1])
                y = float(parts[2])
                z = float(parts[3])
            except ValueError as exc:
                raise ValueError(f"Invalid OBJ vertex line at {line_number}: non-numeric component") from exc
            vertices.append(Vec3(x, y, z))
            continue

        if prefix == "f":
            if len(parts) not in (4, 5):
                raise ValueError(f"Invalid OBJ face line at {line_number}: only triangles and quads are supported")

            face_indices = [_parse_face_vertex_index(token, len(vertices), line_number) for token in parts[1:]]
            if len(face_indices) == 3:
                triangles.append((face_indices[0], face_indices[1], face_indices[2]))
            else:
                triangles.append((face_indices[0], face_indices[1], face_indices[2]))
                triangles.append((face_indices[0], face_indices[2], face_indices[3]))
            continue

    return TriangleMesh.from_vertices(vertices, triangles, name=name or "")


def _parse_face_vertex_index(token: str, vertex_count: int, line_number: int) -> int:
    if not token:
        raise ValueError(f"Invalid OBJ face line at {line_number}: empty face token")

    vertex_index_text = token.split("/", 1)[0]
    if not vertex_index_text:
        raise ValueError(f"Invalid OBJ face line at {line_number}: missing vertex index")

    try:
        vertex_index = int(vertex_index_text)
    except ValueError as exc:
        raise ValueError(f"Invalid OBJ face line at {line_number}: invalid vertex index") from exc

    if vertex_index <= 0:
        raise ValueError(f"Invalid OBJ face line at {line_number}: negative or zero indices are not supported")

    zero_based = vertex_index - 1
    if zero_based >= vertex_count:
        raise ValueError(f"Invalid OBJ face line at {line_number}: vertex index out of range")
    return zero_based
