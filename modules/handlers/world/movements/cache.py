#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""DBC-only movement template cache."""

from __future__ import annotations

from pathlib import Path

from shared.Logger import Logger
from shared.PathUtils import get_dbc_root
from server.modules.dbc import read_dbc

from .templates import build_template
from .types import (
    InterpolationMode,
    MovementKind,
    MovementNode,
    MovementTemplate,
)
from . import templates

TRANSPORT_ANIMATION_FORMAT = "diifffx"
TAXI_PATH_NODE_FORMAT = "diiifffiiii"

LEGACY_ELEVATOR_ENTRIES = {
    4170,
    4171,
    47296,
    47297,
    11898,
    11899,
}


def _movement_node_time(node: MovementNode) -> int:
    return int(node.time_ms)


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


def _legacy_elevator_nodes(entry: int) -> tuple[MovementNode, ...] | None:
    #
    # Thunder Bluff elevators.
    #
    # Elevator model origin is centered, so movement must be
    # symmetrical around zero instead of 0 -> +height.
    #

    if entry in (4170, 47296, 11899):
        #
        # Bottom -> top
        #
        return (
            MovementNode(map_id=1, x=0.0, y=0.0, z=-0.0, time_ms=0),
            MovementNode(map_id=1, x=0.0, y=0.0, z=0.0, time_ms=30000),
        )

    if entry in (4171, 47297, 11898):
        #
        # Top -> bottom
        #
        return (
            MovementNode(map_id=1, x=0.0, y=0.0, z=0.0, time_ms=0),
            MovementNode(map_id=1, x=0.0, y=0.0, z=0.0, time_ms=30000),
        )

    return None

def _inject_legacy_elevator_templates(
    templates: dict[int, MovementTemplate],
) -> None:
    for entry in LEGACY_ELEVATOR_ENTRIES:
        nodes = _legacy_elevator_nodes(entry)

        if nodes is None:
            continue

        template, reason = build_template(
            f"legacy-elevator:{entry}",
            MovementKind.ELEVATOR,
            nodes,
            interpolation_mode=InterpolationMode.LINEAR,
        )

        if template is None:
            Logger.warning(
                "[MovementCache] invalid legacy elevator entry=%s reason=%s",
                entry,
                reason,
            )
            continue

        templates[int(entry)] = template

        Logger.info(
            "[MovementCache] injected legacy elevator entry=%s",
            entry,
        )


def _load_transport_animation_templates() -> dict[int, MovementTemplate]:
    path = _dbc_file("TransportAnimation.dbc")

    if path is None:
        Logger.warning("[MovementCache] missing TransportAnimation.dbc")
        return {}

    grouped: dict[int, list[MovementNode]] = {}

    try:
        rows = read_dbc(path, TRANSPORT_ANIMATION_FORMAT)

    except Exception as exc:
        Logger.warning(
            "[MovementCache] failed TransportAnimation.dbc path=%s err=%s",
            path,
            exc,
        )
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
        ordered_nodes = sorted(
            nodes,
            key=_movement_node_time,
        )

        #
        # Blizzard elevator animation data appears reversed.
        # Reverse node order so elevators move in the correct direction.
        #
        ordered_nodes.reverse()

        ordered = tuple(ordered_nodes)

        if ordered:
            Logger.info(
                (
                    "[ElevatorDebug] entry=%s "
                    "first=(%.2f %.2f %.2f t=%s) "
                    "last=(%.2f %.2f %.2f t=%s)"
                ),
                entry,
                ordered[0].x,
                ordered[0].y,
                ordered[0].z,
                ordered[0].time_ms,
                ordered[-1].x,
                ordered[-1].y,
                ordered[-1].z,
                ordered[-1].time_ms,
            )

        template, reason = build_template(
            f"transport-animation:{entry}",
            MovementKind.ELEVATOR,
            ordered,
            interpolation_mode=InterpolationMode.LINEAR,
        )

        if template is None:
            Logger.warning(
                "[MovementCache] invalid TransportAnimation entry=%s reason=%s",
                entry,
                reason,
            )
            continue

        templates[int(entry)] = template

    _inject_legacy_elevator_templates(templates)
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
        Logger.warning(
            "[MovementCache] failed TaxiPathNode.dbc path=%s err=%s",
            path,
            exc,
        )
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
        ordered_source_nodes = sorted(
            nodes,
            key=_movement_node_time,
        )

        ordered_nodes = tuple(
            MovementNode(
                map_id=node.map_id,
                x=node.x,
                y=node.y,
                z=node.z,
                time_ms=int(node.time_ms),
            )
            for node in ordered_source_nodes
        )

        template, reason = build_template(
            f"taxi-path:{path_id}",
            MovementKind.TAXI,
            ordered_nodes,
            interpolation_mode=InterpolationMode.SPLINE,
        )

        if template is None:
            Logger.warning(
                "[MovementCache] invalid TaxiPathNode path=%s reason=%s",
                path_id,
                reason,
            )
            continue

        templates[int(path_id)] = template

    return templates