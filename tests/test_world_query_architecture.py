from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

from server.modules.handlers.world.query import WorldQuery


_WORLD_ROOT = Path(__file__).parents[1] / "modules" / "handlers" / "world"
_MIGRATED_GAMEPLAY_MODULES = (_WORLD_ROOT / "opcodes" / "movement.py",)


def _imports_in(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(str(node.module or ""))
    return imports


def test_gameplay_modules_do_not_import_collision_query_backends_directly():
    forbidden = {
        "server.modules.handlers.world.collision.geometry_shadow",
        "server.modules.handlers.world.collision.gameobject_collision",
    }
    violations: list[str] = []
    for path in _MIGRATED_GAMEPLAY_MODULES:
        direct = _imports_in(path) & forbidden
        if direct:
            violations.append(f"{path.relative_to(_WORLD_ROOT)}: {sorted(direct)}")
    assert violations == []


def test_movement_uses_world_query_as_collision_entry_point():
    movement = (_WORLD_ROOT / "opcodes" / "movement.py").read_text(encoding="utf-8")
    assert "from server.modules.handlers.world.query import WorldQuery" in movement
    assert "WorldQuery.query_collision(" in movement
    assert "WorldQuery.query_geometry_shadow(" in movement
    assert "gameobject_collision_index.blocked(" not in movement
    assert "run_geometry_shadow_comparison(" not in movement


def test_world_query_collision_delegates_without_changing_result(monkeypatch):
    collision = SimpleNamespace(guid=17)
    class Index:
        def blocked(self, map_id, start, end):
            return collision

        def __len__(self):
            return 3

    index = Index()
    monkeypatch.setattr(
        "server.modules.handlers.world.collision.gameobject_collision_index",
        index,
    )

    result = WorldQuery.query_collision(
        map_id=1,
        start=(1.0, 2.0, 3.0),
        end=(4.0, 5.0, 6.0),
    )

    assert result.collision is collision
    assert result.registered_objects == 3


def test_world_query_service_has_no_world_session_dependency():
    source = (_WORLD_ROOT / "query" / "service.py").read_text(encoding="utf-8")
    assert "WorldSession" not in source.replace("No method accepts or reads WorldSession", "")
    assert "session" not in {
        argument.arg
        for node in ast.walk(ast.parse(source))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        for argument in (*node.args.args, *node.args.kwonlyargs)
    }
