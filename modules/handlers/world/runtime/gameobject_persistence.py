#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Explicit serialization boundary for persistent runtime GameObjects."""

from __future__ import annotations

from typing import Any, Mapping

from server.modules.handlers.world.runtime.gameobject import GameObject


def gameobject_persistence_snapshot(
    gameobject: GameObject,
    mapping: Mapping[str, Any],
) -> dict[str, Any]:
    """Serialize runtime-authoritative values into a persistence snapshot.

    Template and persistent spawn metadata are copied from ``mapping``. The
    returned dictionary is independent of both inputs and performs no database,
    cache, packet, collision, visibility, or lifecycle work.
    """
    snapshot = dict(mapping)
    snapshot.update(
        {
            "guid": int(gameobject.spawn_id),
            "entry": int(gameobject.entry),
            "map_id": int(gameobject.map_id),
            "map": int(gameobject.map_id),
            "x": float(gameobject.x),
            "y": float(gameobject.y),
            "z": float(gameobject.z),
            "orientation": float(gameobject.orientation),
            "rotation0": float(gameobject.rotation[0]),
            "rotation1": float(gameobject.rotation[1]),
            "rotation2": float(gameobject.rotation[2]),
            "rotation3": float(gameobject.rotation[3]),
            "size": float(gameobject.scale),
            "display_id": int(gameobject.display_id),
            "state": int(gameobject.state),
            "flags": int(gameobject.flags),
            "faction": int(gameobject.faction),
            "artkit": int(gameobject.art_kit),
            "animprogress": int(gameobject.animation_progress),
            "type": int(gameobject.gameobject_type),
        }
    )
    return snapshot
