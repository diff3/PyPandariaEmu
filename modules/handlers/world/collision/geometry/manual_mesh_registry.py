from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .mesh import TriangleMesh
from .obj_loader import load_obj_mesh


ONYXIA_TROPHY_ENTRY = 179881
ONYXIA_TROPHY_DISPLAY_ID = 5951


@dataclass(frozen=True)
class ManualMeshSpec:
    display_id: int
    entry: int
    mesh_name: str
    obj_path: Path


_ASSET_ROOT = Path(__file__).resolve().parent / "assets"

_MANUAL_MESH_REGISTRY: dict[int, ManualMeshSpec] = {
    ONYXIA_TROPHY_DISPLAY_ID: ManualMeshSpec(
        display_id=ONYXIA_TROPHY_DISPLAY_ID,
        entry=ONYXIA_TROPHY_ENTRY,
        mesh_name="manual_onyxia_trophy_5951",
        obj_path=_ASSET_ROOT / "onyxia_trophy_5951.obj",
    ),
}

_MANUAL_MESH_CACHE: dict[int, TriangleMesh] = {}


def get_manual_mesh_spec(display_id: int) -> ManualMeshSpec | None:
    return _MANUAL_MESH_REGISTRY.get(int(display_id))


def load_manual_mesh_for_display(display_id: int) -> TriangleMesh | None:
    spec = get_manual_mesh_spec(display_id)
    if spec is None:
        return None
    cached = _MANUAL_MESH_CACHE.get(spec.display_id)
    if cached is not None:
        return cached
    mesh = load_obj_mesh(str(spec.obj_path), name=spec.mesh_name)
    _MANUAL_MESH_CACHE[spec.display_id] = mesh
    return mesh


def clear_manual_mesh_cache() -> None:
    _MANUAL_MESH_CACHE.clear()
