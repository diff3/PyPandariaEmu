#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Explicit serialization boundary for persistent runtime Creatures."""

from __future__ import annotations

from typing import Any, Mapping

from server.modules.handlers.world.runtime.creature import Creature


def creature_persistence_snapshot(
    creature: Creature,
    mapping: Mapping[str, Any],
) -> dict[str, Any]:
    """Serialize runtime-authoritative values into a persistence snapshot.

    Creature-specific persistent metadata is copied from ``mapping``. The
    returned dictionary is independent of both inputs and performs no database,
    packet, visibility, lifecycle, AI, movement, or gameplay work.
    """
    snapshot = dict(mapping)
    snapshot.update(
        {
            "guid": int(creature.spawn_id),
            "entry": int(creature.entry),
            "map_id": int(creature.map_id),
            "map": int(creature.map_id),
            "x": float(creature.x),
            "y": float(creature.y),
            "z": float(creature.z),
            "orientation": float(creature.orientation),
            "rotation0": float(creature.rotation[0]),
            "rotation1": float(creature.rotation[1]),
            "rotation2": float(creature.rotation[2]),
            "rotation3": float(creature.rotation[3]),
            "size": float(creature.scale),
            "modelid": int(creature.display_id),
            "npcflag": int(creature.npc_flags),
        }
    )
    return snapshot
