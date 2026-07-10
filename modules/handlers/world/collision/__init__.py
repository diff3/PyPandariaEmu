"""Lightweight authoritative collision for ordinary static GameObjects."""

from .gameobject_collision import (
    build_gameobject_collision_index,
    clear_gameobject_collision_index,
    gameobject_collision_index,
)

__all__ = [
    "build_gameobject_collision_index",
    "clear_gameobject_collision_index",
    "gameobject_collision_index",
]
