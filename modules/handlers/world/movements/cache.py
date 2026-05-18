#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""DBC-only movement template cache."""

from __future__ import annotations

from pathlib import Path

from shared.Logger import Logger
from shared.PathUtils import get_dbc_root
from server.modules.dbc import read_dbc

from .templates import build_template
from .types import MovementKind, MovementNode, MovementTemplate

TRANSPORT_ANIMATION_FORMAT = "diifffx"
TAXI_PATH_NODE_FORMAT = "diiifffiiii"


class MovementTemplateCache:
    def __init__(self) -> None:
        self.transport_animation: dict[int, MovementTemplate] = {}
        self.taxi_paths: dict[int, MovementTemplate] = {}
        self.loaded = False

    def load(self) -> None:
        if self.loaded:
            return
        self.transport_animation = _load_transport_animation_templates()
        self.taxi_paths = _load_taxi_path_templates()
        self.loaded = True
        Logger.info(
            "[MovementCache] loaded transport_animation=%s taxi_paths=%s",
            len(self.transport_animation),
            len(self.taxi_paths),
        )

    def transport_template(self, entry: int) -> MovementTemplate | None:
        self.load()
        return self.transport_animation.get(int(entry))

    def taxi_template(self, path_id: int) -> MovementTemplate | None:
        self.load()
        return self.taxi_paths.get(int(path_id))


_CACHE = MovementTemplateCache()


def get_movement_cache() -> MovementTemplateCache:
    return _CACHE


def _dbc_file(filename: str) -> Path | None:
    root = get_dbc_root()
    if root is None:
        return None
    candidate = Path(root) / filename
    return candidate if candidate.exists() else None


def _load_transport_animation_templates() -> dict[int, MovementTemplate]:
    path = _dbc_file("TransportAnimation.dbc")
    if path is None:
        Logger.warning("[MovementCache] missing TransportAnimation.dbc")
        return {}

    grouped: dict[int, list[MovementNode]] = {}
    try:
        rows = read_dbc(path, TRANSPORT_ANIMATION_FORMAT)
    except Exception as exc:
        Logger.warning("[MovementCache] failed TransportAnimation.dbc path=%s err=%s", path, exc)
        return {}

    for row in rows:
        try:
            entry = int(row[1])
            node = MovementNode(
                map_id=0,
                x=float(row[3]),
                y=float(row[4]),
                z=float(row[5]),
                time_ms=max(0, int(row[2])),
            )
        except (TypeError, ValueError, IndexError):
            continue
        grouped.setdefault(entry, []).append(node)

    templates: dict[int, MovementTemplate] = {}
    for entry, nodes in grouped.items():
        ordered = tuple(sorted(nodes, key=lambda node: int(node.time_ms)))
        template, reason = build_template(f"transport-animation:{entry}", MovementKind.ELEVATOR, ordered)
        if template is None:
            Logger.warning("[MovementCache] invalid TransportAnimation entry=%s reason=%s", entry, reason)
            continue
        templates[int(entry)] = template
    return templates


def _load_taxi_path_templates() -> dict[int, MovementTemplate]:
    path = _dbc_file("TaxiPathNode.dbc")
    if path is None:
        Logger.warning("[MovementCache] missing TaxiPathNode.dbc")
        return {}

    grouped: dict[int, list[MovementNode]] = {}
    try:
        rows = read_dbc(path, TAXI_PATH_NODE_FORMAT)
    except Exception as exc:
        Logger.warning("[MovementCache] failed TaxiPathNode.dbc path=%s err=%s", path, exc)
        return {}

    for row in rows:
        try:
            path_id = int(row[1])
            node = MovementNode(
                map_id=int(row[3]),
                x=float(row[4]),
                y=float(row[5]),
                z=float(row[6]),
                time_ms=max(0, int(row[2])),
            )
        except (TypeError, ValueError, IndexError):
            continue
        grouped.setdefault(path_id, []).append(node)

    templates: dict[int, MovementTemplate] = {}
    for path_id, nodes in grouped.items():
        ordered_nodes = tuple(
            MovementNode(
                map_id=node.map_id,
                x=node.x,
                y=node.y,
                z=node.z,
                time_ms=index,
            )
            for index, node in enumerate(sorted(nodes, key=lambda item: int(item.time_ms)))
        )
        template, reason = build_template(f"taxi-path:{path_id}", MovementKind.TAXI, ordered_nodes)
        if template is None:
            Logger.warning("[MovementCache] invalid TaxiPathNode path=%s reason=%s", path_id, reason)
            continue
        templates[int(path_id)] = template
    return templates
