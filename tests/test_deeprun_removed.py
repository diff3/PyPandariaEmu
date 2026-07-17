from pathlib import Path
from types import SimpleNamespace


WORLD_ROOT = Path(__file__).parents[1] / "modules" / "handlers" / "world"


def test_deeprun_production_module_is_removed():
    assert not (WORLD_ROOT / "features" / "deeprun_collision.py").exists()


def test_deeprun_identifiers_are_absent_from_production_code():
    forbidden = (
        "deeprun",
        "deep run",
        "_static_type11",
        "176080",
        "176081",
        "176082",
        "176083",
        "176084",
        "176085",
        "194675",
    )

    matches: list[str] = []
    for path in WORLD_ROOT.rglob("*.py"):
        source = path.read_text(encoding="utf-8").lower()
        for marker in forbidden:
            if marker in source:
                matches.append(f"{path.relative_to(WORLD_ROOT)}: {marker}")

    assert matches == []


def test_generic_transport_framework_remains_available():
    from server.modules.handlers.world import transport_runtime
    from server.modules.handlers.world.movements.types import MovementKind

    assert transport_runtime.WorldTransportManager is not None
    assert transport_runtime.RuntimeTransportState is not None
    assert MovementKind.TRANSPORT.value == "transport"
    assert MovementKind.ELEVATOR.value == "elevator"


def test_static_type11_gameobject_is_not_an_attachable_transport():
    from server.modules.handlers.world import transport_runtime

    world_guid = 0xF11000000007A121
    session = SimpleNamespace(
        char_guid=16,
        map_id=369,
        loaded_gameobjects={world_guid},
        loaded_gameobject_entries={
            world_guid: {
                "world_guid": world_guid,
                "entry": 176082,
                "map": 369,
                "type": transport_runtime.GAMEOBJECT_TYPE_TRANSPORT,
            }
        },
    )

    transport_runtime._runtime_transport_states().pop(world_guid, None)

    assert transport_runtime.can_attach_transport(session, world_guid) is False
