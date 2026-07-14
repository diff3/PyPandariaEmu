#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared runtime representations and lifecycle services."""

from server.modules.handlers.world.runtime.creature import Creature
from server.modules.handlers.world.runtime.creature_persistence import (
    creature_persistence_snapshot,
)
from server.modules.handlers.world.runtime.creature_store import (
    CreatureRuntimeStore,
    get_creature_runtime_store,
)
from server.modules.handlers.world.runtime.gameobject import GameObject
from server.modules.handlers.world.runtime.gameobject_persistence import (
    gameobject_persistence_snapshot,
)
from server.modules.handlers.world.runtime.gameobject_store import (
    GameObjectRuntimeStore,
    get_gameobject_runtime_store,
)
from server.modules.handlers.world.runtime.runtime_object import RuntimeObject
from server.modules.handlers.world.runtime.runtime_store import RuntimeStore
from server.modules.handlers.world.runtime.spawned_world_object import (
    SpawnedWorldObject,
    resolve_spawned_world_object,
)
from server.modules.handlers.world.runtime.transport import Transport
from server.modules.handlers.world.runtime.world_object import WorldObject

__all__ = [
    "Creature",
    "CreatureRuntimeStore",
    "GameObject",
    "GameObjectRuntimeStore",
    "RuntimeObject",
    "RuntimeStore",
    "SpawnedWorldObject",
    "Transport",
    "WorldObject",
    "get_creature_runtime_store",
    "get_gameobject_runtime_store",
    "creature_persistence_snapshot",
    "gameobject_persistence_snapshot",
    "resolve_spawned_world_object",
]
