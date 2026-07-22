from types import SimpleNamespace

from server.modules.handlers.world.runtime.player import Player
from server.modules.handlers.world.teleport.gameobject_teleport import (
    _is_at_interaction_distance,
)


def _player_at(x: float, y: float, z: float) -> Player:
    return Player.from_session(
        SimpleNamespace(
            char_guid=1,
            world_guid=1,
            map_id=0,
            instance_id=0,
            x=x,
            y=y,
            z=z,
            orientation=0.0,
        )
    )


def test_gameobject_interaction_distance_uses_player_geometry():
    entry = {"x": 10.0, "y": 0.0, "z": 0.0, "size": 1.0}

    assert _is_at_interaction_distance(_player_at(0.0, 0.0, 0.0), entry) is True
    assert _is_at_interaction_distance(_player_at(-0.01, 0.0, 0.0), entry) is False


def test_gameobject_interaction_distance_preserves_scaled_radius():
    entry = {"x": 15.0, "y": 0.0, "z": 0.0, "size": 3.0}

    assert _is_at_interaction_distance(_player_at(0.0, 0.0, 0.0), entry) is True
    assert _is_at_interaction_distance(_player_at(-0.01, 0.0, 0.0), entry) is False
