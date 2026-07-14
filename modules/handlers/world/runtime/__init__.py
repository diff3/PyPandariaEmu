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
from server.modules.handlers.world.runtime.elevator import Elevator
from server.modules.handlers.world.runtime.elevator_store import (
    ElevatorRuntimeStore,
    get_elevator_runtime_store,
    resolve_elevator_runtime,
)
from server.modules.handlers.world.runtime.gameobject import GameObject
from server.modules.handlers.world.runtime.gameobject_persistence import (
    gameobject_persistence_snapshot,
)
from server.modules.handlers.world.runtime.gameobject_store import (
    GameObjectRuntimeStore,
    get_gameobject_runtime_store,
)
from server.modules.handlers.world.runtime.player import Player
from server.modules.handlers.world.runtime.player_store import (
    PlayerRuntimeStore,
    get_player_runtime_store,
    resolve_player_runtime,
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
    "Elevator",
    "ElevatorRuntimeStore",
    "GameObject",
    "GameObjectRuntimeStore",
    "Player",
    "PlayerRuntimeStore",
    "RuntimeObject",
    "RuntimeStore",
    "SpawnedWorldObject",
    "Transport",
    "WorldObject",
    "get_creature_runtime_store",
    "get_elevator_runtime_store",
    "get_gameobject_runtime_store",
    "get_player_runtime_store",
    "resolve_player_runtime",
    "resolve_elevator_runtime",
    "creature_persistence_snapshot",
    "gameobject_persistence_snapshot",
    "resolve_spawned_world_object",
]
