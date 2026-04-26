#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PlayerVisibleEquipmentSlot:
    slot: int
    entry: int
    display_id: int
    inventory_type: int


@dataclass(frozen=True)
class PlayerVisibleSnapshot:
    guid: int
    name: str
    map_id: int
    zone: int
    x: float
    y: float
    z: float
    orientation: float
    movement_flags: int
    movement_flags2: int
    is_mounted: bool
    unit_flags: int
    mount_display_id: int
    equipment_cache_raw: tuple[int, ...]
    visible_equipment: tuple[PlayerVisibleEquipmentSlot, ...]
    walk_speed: float
    run_speed: float
    run_back_speed: float
    swim_speed: float
    swim_back_speed: float
    fly_speed: float
    fly_back_speed: float
    turn_speed: float
    pitch_speed: float


def _to_int(value: Any, default: int = 0) -> int:
    if value is None or value == "":
        return int(default)
    try:
        return int(value)
    except Exception:
        return int(default)


def _to_float(value: Any, default: float = 0.0) -> float:
    if value is None or value == "":
        return float(default)
    try:
        return float(value)
    except Exception:
        return float(default)


def _equipment_cache_tuple(session: Any) -> tuple[int, ...]:
    values: list[int] = []
    for value in getattr(session, "equipment_cache_raw", ()) or ():
        values.append(_to_int(value))
    return tuple(values)


def _visible_equipment_slots(session: Any) -> tuple[PlayerVisibleEquipmentSlot, ...]:
    state = getattr(session, "inventory_state", None)
    slots: list[PlayerVisibleEquipmentSlot] = []
    for slot in range(19):
        item = state.get(0, slot) if state is not None and hasattr(state, "get") else None
        slots.append(
            PlayerVisibleEquipmentSlot(
                slot=slot,
                entry=_to_int(getattr(item, "entry", 0)),
                display_id=_to_int(getattr(item, "display_id", 0)),
                inventory_type=_to_int(getattr(item, "inventory_type", 0)),
            )
        )
    return tuple(slots)


def build_player_visible_snapshot(session: Any) -> PlayerVisibleSnapshot:
    movement_state = getattr(session, "movement_state", None)
    return PlayerVisibleSnapshot(
        guid=_to_int(
            getattr(session, "char_guid", 0)
            or getattr(session, "player_guid", 0)
            or getattr(session, "world_guid", 0)
        ),
        name=str(getattr(session, "player_name", "") or ""),
        map_id=_to_int(getattr(session, "map_id", 0)),
        zone=_to_int(getattr(session, "zone", 0)),
        x=_to_float(getattr(session, "x", 0.0)),
        y=_to_float(getattr(session, "y", 0.0)),
        z=_to_float(getattr(session, "z", 0.0)),
        orientation=_to_float(getattr(session, "orientation", 0.0)),
        movement_flags=_to_int(getattr(movement_state, "flags", 0)),
        movement_flags2=_to_int(getattr(movement_state, "flags2", 0)),
        is_mounted=bool(getattr(session, "is_mounted", False)),
        unit_flags=_to_int(getattr(session, "unit_flags", 0)),
        mount_display_id=_to_int(getattr(session, "mount_display_id", 0)),
        equipment_cache_raw=_equipment_cache_tuple(session),
        visible_equipment=_visible_equipment_slots(session),
        walk_speed=_to_float(getattr(session, "walk_speed", 2.5), 2.5),
        run_speed=_to_float(getattr(session, "run_speed", 7.0), 7.0),
        run_back_speed=_to_float(getattr(session, "run_back_speed", 4.5), 4.5),
        swim_speed=_to_float(getattr(session, "swim_speed", 4.7), 4.7),
        swim_back_speed=_to_float(getattr(session, "swim_back_speed", 2.5), 2.5),
        fly_speed=_to_float(getattr(session, "fly_speed", 7.0), 7.0),
        fly_back_speed=_to_float(getattr(session, "fly_back_speed", 4.5), 4.5),
        turn_speed=_to_float(getattr(session, "turn_speed", 3.1415926), 3.1415926),
        pitch_speed=_to_float(getattr(session, "pitch_speed", 3.1415926), 3.1415926),
    )
