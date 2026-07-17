from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_player_movement_has_no_gameobject_collision_queries():
    source = (PROJECT_ROOT / "server/modules/handlers/world/opcodes/movement.py").read_text()

    assert "gameobject_collision" not in source
    assert "GOCollision" not in source
    assert "query_collision(" not in source
    assert "query_geometry_shadow(" not in source


def test_gameobject_runtime_has_no_collision_index_lifecycle():
    source = (PROJECT_ROOT / "server/modules/handlers/world/runtime/gameobject_spawns.py").read_text()

    assert "_create_collision" not in source
    assert "_remove_collision" not in source
    assert "geometry_shadow" not in source


def test_experimental_collision_modules_and_config_are_removed():
    assert not (PROJECT_ROOT / "server/modules/handlers/world/collision/gameobject_collision.py").exists()
    assert not (PROJECT_ROOT / "server/modules/handlers/world/collision/geometry_shadow.py").exists()

    config = (PROJECT_ROOT / "config/default.yaml").read_text()
    assert "EnableGameObjectCollision" not in config
    assert "GameObjectCollisionMode" not in config
    assert "ExperimentalGeometryShadow" not in config
