#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Any

from shared.Logger import Logger
from shared.PathUtils import get_dbc_root


_AREA_NAME_FIELD_INDEX = 13
_WORLD_MAP_IDS = {0, 1, 530, 571, 870}
_NORMALIZE_RE = re.compile(r"[^a-z0-9]+")
_INTERNAL_ZONE_NAMES = {
    "city",
    "class quest",
    "do not use",
    "programmer isle",
}


@dataclass(frozen=True)
class WeatherZoneEntry:
    zone_id: int
    parent_zone_id: int
    map_id: int
    name: str
    normalized_name: str
    aliases: tuple[str, ...] = field(default_factory=tuple)
    child_zone_ids: tuple[int, ...] = field(default_factory=tuple)
    explicit_weather: bool = False


@dataclass(frozen=True)
class AreaTableEntry:
    area_id: int
    parent_area_id: int
    map_id: int
    name: str


def canonical_weather_zone_registry(
    explicit_weather_zone_ids: set[int] | None = None,
) -> dict[int, WeatherZoneEntry]:
    areas = area_table_entries()
    if not areas:
        return {}

    explicit = {
        int(zone_id)
        for zone_id in (explicit_weather_zone_ids or set())
        if int(zone_id or 0) > 0
    }
    children: dict[int, list[int]] = {}
    for area in areas.values():
        if area.parent_area_id > 0:
            children.setdefault(area.parent_area_id, []).append(area.area_id)

    canonical_ids = {
        area.area_id
        for area in areas.values()
        if _is_root_weather_zone(area)
    }
    canonical_ids.update(zone_id for zone_id in explicit if zone_id in areas)

    registry: dict[int, WeatherZoneEntry] = {}
    for zone_id in sorted(canonical_ids):
        area = areas.get(zone_id)
        if area is None or not _is_visible_weather_area(area):
            continue
        alias_names = _alias_names_for_zone(zone_id, areas, children, explicit)
        registry[zone_id] = WeatherZoneEntry(
            zone_id=zone_id,
            parent_zone_id=int(area.parent_area_id),
            map_id=int(area.map_id),
            name=area.name,
            normalized_name=normalize_zone_search(area.name),
            aliases=tuple(alias_names),
            child_zone_ids=tuple(sorted(children.get(zone_id, ()))),
            explicit_weather=zone_id in explicit,
        )
    return registry


def area_table_entries() -> dict[int, AreaTableEntry]:
    cached = getattr(area_table_entries, "_cache", None)
    if isinstance(cached, dict):
        return dict(cached)

    dbc_root = get_dbc_root()
    path = dbc_root / "AreaTable.dbc" if dbc_root is not None else None
    if path is None or not path.exists():
        setattr(area_table_entries, "_cache", {})
        return {}

    try:
        with path.open("rb") as handle:
            if handle.read(4) != b"WDBC":
                setattr(area_table_entries, "_cache", {})
                return {}
            record_count, field_count, record_size, string_size = struct.unpack("<4I", handle.read(16))
            records = [handle.read(record_size) for _ in range(record_count)]
            string_block = handle.read(string_size)
    except Exception as exc:
        Logger.warning("[WeatherZoneRegistry] AreaTable.dbc load failed err=%s", exc)
        setattr(area_table_entries, "_cache", {})
        return {}

    if int(field_count) <= _AREA_NAME_FIELD_INDEX:
        setattr(area_table_entries, "_cache", {})
        return {}

    entries: dict[int, AreaTableEntry] = {}
    for record in records:
        if len(record) != int(record_size):
            continue
        area_id = int(struct.unpack_from("<I", record, 0)[0])
        if area_id <= 0:
            continue
        map_id = int(struct.unpack_from("<i", record, 4)[0])
        parent_area_id = int(struct.unpack_from("<I", record, 8)[0])
        name_offset = int(struct.unpack_from("<I", record, _AREA_NAME_FIELD_INDEX * 4)[0])
        name = _dbc_string(string_block, name_offset)
        if not name:
            continue
        entries[area_id] = AreaTableEntry(
            area_id=area_id,
            parent_area_id=parent_area_id,
            map_id=map_id,
            name=name,
        )

    setattr(area_table_entries, "_cache", dict(entries))
    return dict(entries)


def normalize_zone_search(value: Any) -> str:
    normalized = _NORMALIZE_RE.sub(" ", str(value or "").strip().lower())
    return " ".join(normalized.split())


def canonical_zone_for_area(
    area_id: int,
    explicit_weather_zone_ids: set[int] | None = None,
) -> int:
    areas = area_table_entries()
    explicit = {
        int(zone_id)
        for zone_id in (explicit_weather_zone_ids or set())
        if int(zone_id or 0) > 0
    }
    current = int(area_id or 0)
    seen: set[int] = set()
    fallback = current
    while current > 0 and current not in seen:
        seen.add(current)
        area = areas.get(current)
        if area is None:
            return fallback
        if current in explicit or area.parent_area_id <= 0:
            return current
        fallback = current
        current = int(area.parent_area_id)
    return fallback


def _is_root_weather_zone(area: AreaTableEntry) -> bool:
    return (
        int(area.parent_area_id) <= 0
        and _is_visible_weather_area(area)
    )


def _is_visible_weather_area(area: AreaTableEntry) -> bool:
    name = str(area.name or "").strip()
    normalized_name = name.lower()
    return (
        bool(name)
        and int(area.map_id) in _WORLD_MAP_IDS
        and normalized_name not in _INTERNAL_ZONE_NAMES
        and not normalized_name.startswith("unused")
        and "do not use" not in normalized_name
    )


def _alias_names_for_zone(
    zone_id: int,
    areas: dict[int, AreaTableEntry],
    children: dict[int, list[int]],
    explicit_weather_zone_ids: set[int],
) -> list[str]:
    aliases: list[str] = []
    for child_id in sorted(children.get(int(zone_id), ())):
        if child_id in explicit_weather_zone_ids:
            continue
        child = areas.get(child_id)
        if child is None or not _is_visible_weather_area(child):
            continue
        aliases.append(child.name)
    return aliases


def _dbc_string(block: bytes, offset: int) -> str:
    if int(offset) <= 0 or int(offset) >= len(block):
        return ""
    end = block.find(b"\x00", int(offset))
    if end < 0:
        end = len(block)
    return block[int(offset):end].decode("utf-8", errors="ignore").strip()
