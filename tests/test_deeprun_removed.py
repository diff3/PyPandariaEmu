from pathlib import Path
from types import SimpleNamespace


WORLD_ROOT = Path(__file__).parents[1] / "modules" / "handlers" / "world"


def test_deeprun_has_no_custom_route_or_feature_module():
    project_root = WORLD_ROOT.parents[3]

    assert not (WORLD_ROOT / "features" / "deeprun_collision.py").exists()
    assert not (project_root / "data" / "transports" / "runtime_routes.json").exists()


def test_legacy_world_entries_resolve_to_canonical_dbc_transport_entries():
    from server.modules.handlers.world import transport_runtime

    expected = {
        176080: 218203,
        176081: 218204,
        176082: 218205,
        176083: 218206,
        176084: 218207,
        176085: 218208,
    }

    assert {
        entry: transport_runtime._canonical_local_transport_entry_id(entry)
        for entry in expected
    } == expected


def test_deeprun_uses_transport_animation_dbc_through_normal_runtime():
    from server.modules.handlers.world import transport_runtime

    entry = {
        "guid": 18802,
        "entry": 176080,
        "map": 369,
        "type": transport_runtime.GAMEOBJECT_TYPE_TRANSPORT,
        "display_id": 3831,
        "x": 4.58065,
        "y": 28.2097,
        "z": 7.01107,
        "orientation": 1.5708,
        "rotation0": 0.0,
        "rotation1": 0.0,
        "rotation2": 1.0,
        "rotation3": 0.0,
    }

    prepared = transport_runtime.prepare_runtime_transport_entry(entry)

    assert prepared["db_entry"] == 176080
    assert prepared["entry"] == 218203
    assert prepared["client_driven_transport_animation"] is True
    assert prepared["transport_period"] == 143333
    assert "runtime_route" not in prepared
    animation = transport_runtime._transport_animation_for_entry(prepared["entry"])
    assert animation is not None
    assert len(animation.nodes) == 53
    route = transport_runtime._build_dbc_animation_route(prepared)
    assert max(node.y for node in route) > 2400.0
    assert max(abs(node.x - entry["x"]) for node in route) < 0.01


def test_deeprun_registers_as_normal_transport_not_elevator():
    from server.modules.game.guid import MoTransportGuid
    from server.modules.handlers.world import transport_runtime

    transport_runtime.reset_world_transport_manager_for_tests()
    entry = transport_runtime.prepare_runtime_transport_entry(
        {
            "guid": 18802,
            "entry": 176080,
            "map": 369,
            "type": transport_runtime.GAMEOBJECT_TYPE_TRANSPORT,
            "display_id": 3831,
            "x": 4.58065,
            "y": 28.2097,
            "z": 7.01107,
            "orientation": 1.5708,
            "rotation0": 0.0,
            "rotation1": 0.0,
            "rotation2": 1.0,
            "rotation3": 0.0,
        }
    )
    entry["world_guid"] = int(MoTransportGuid.from_spawn_guid(entry["guid"]))

    state = transport_runtime.get_world_transport_manager().register_transport(
        entry,
        source="test",
    )

    assert state is not None
    assert state.route_period_ms == 143333
    assert transport_runtime.get_world_transport_manager().transport_for_guid(
        entry["world_guid"]
    ) is not None
    assert transport_runtime.get_world_transport_manager().elevator_for_guid(
        entry["world_guid"]
    ) is None
    transport_runtime.reset_world_transport_manager_for_tests()


def test_deeprun_create_preserves_parent_quaternion_instead_of_runtime_yaw():
    from server.modules.game.guid import MoTransportGuid
    from server.modules.handlers.world import transport_runtime
    from server.modules.handlers.world.bootstrap import gameobjects
    from server.modules.handlers.world.runtime.gameobject import GameObject

    transport_runtime.reset_world_transport_manager_for_tests()
    entry = transport_runtime.prepare_runtime_transport_entry(
        {
            "guid": 18802,
            "entry": 176080,
            "map": 369,
            "type": transport_runtime.GAMEOBJECT_TYPE_TRANSPORT,
            "display_id": 3831,
            "x": 4.58065,
            "y": 28.2097,
            "z": 7.01107,
            "orientation": 1.5708,
            "rotation0": 0.0,
            "rotation1": 0.0,
            "rotation2": 1.0,
            "rotation3": 0.0,
        }
    )
    world_guid = int(MoTransportGuid.from_spawn_guid(entry["guid"]))
    entry["world_guid"] = world_guid
    state = transport_runtime.get_world_transport_manager().register_transport(
        entry,
        source="test",
    )
    assert state is not None
    transport = transport_runtime.get_world_transport_manager().transport_for_guid(world_guid)
    gameobject = GameObject.from_mapping(entry, runtime_guid=world_guid)

    packet_entry = gameobjects._transport_runtime_packet_entry(
        entry,
        gameobject,
        transport,
    )

    assert packet_entry["_runtime_transport_orientation_authoritative"] is False
    assert gameobjects._rotation_components(packet_entry, gameobject) == (
        0.0,
        0.0,
        1.0,
        0.0,
    )
    assert gameobjects._stationary_orientation(packet_entry, gameobject) == gameobject.orientation
    transport_runtime.reset_world_transport_manager_for_tests()


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
