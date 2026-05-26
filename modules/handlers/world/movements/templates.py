#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Template builders for DBC-backed movement data."""

from __future__ import annotations

from .interpolation import build_arc_lengths
from .types import (
    InterpolationMode,
    MovementKind,
    MovementNode,
    MovementTemplate,
)
from .validation import validate_template


def build_template(
    template_id: str,
    kind: MovementKind,
    nodes: tuple[MovementNode, ...],
    *,
    interpolation_mode: InterpolationMode,
    period_ms: int | None = None,
) -> tuple[MovementTemplate | None, str]:
    """Build immutable cached movement template."""

    if len(nodes) < 2:
        return None, "node count < 2"

    resolved_period = _resolve_period_ms(nodes, period_ms)

    transfer_nodes = _transfer_nodes(nodes)
    station_nodes = _station_nodes(nodes)

    arc_lengths = build_arc_lengths(
        tuple(nodes),
        interpolation_mode=interpolation_mode,
    )

    total_length = 0.0
    if arc_lengths:
        total_length = float(arc_lengths[-1].distance)

    template = MovementTemplate(
        template_id=str(template_id),
        kind=kind,
        nodes=tuple(nodes),
        period_ms=int(resolved_period),
        interpolation_mode=interpolation_mode,
        arc_lengths=arc_lengths,
        total_length=total_length,
        transfer_nodes=transfer_nodes,
        station_nodes=station_nodes,
    )

    valid, reason = validate_template(template)
    if not valid:
        return None, reason

    return template, ""


def _resolve_period_ms(
    nodes: tuple[MovementNode, ...],
    period_ms: int | None,
) -> int:
    """Resolve template period."""

    if period_ms is not None and int(period_ms) > 0:
        return int(period_ms)

    largest_node_time = max(int(node.time_ms) for node in nodes)
    if largest_node_time > 0:
        return largest_node_time

    return _period_from_node_distances(nodes)


def _transfer_nodes(
    nodes: tuple[MovementNode, ...],
) -> tuple[int, ...]:
    """Collect transfer nodes."""

    result: list[int] = []

    for index, node in enumerate(nodes[:-1]):
        next_node = nodes[index + 1]

        if int(node.map_id) != int(next_node.map_id):
            result.append(index)
            continue

        if bool(node.transfer):
            result.append(index)

    return tuple(result)


def _station_nodes(
    nodes: tuple[MovementNode, ...],
) -> tuple[int, ...]:
    """Collect station nodes."""

    result: list[int] = []

    for index, node in enumerate(nodes):
        if bool(node.station):
            result.append(index)

    return tuple(result)


def _period_from_node_distances(
    nodes: tuple[MovementNode, ...],
) -> int:
    """Estimate fallback movement period from path distance."""

    total_distance = 0.0

    for current, target in zip(nodes, nodes[1:]):
        if int(current.map_id) != int(target.map_id):
            continue

        dx = float(target.x) - float(current.x)
        dy = float(target.y) - float(current.y)
        dz = float(target.z) - float(current.z)

        total_distance += (
            (dx * dx)
            + (dy * dy)
            + (dz * dz)
        ) ** 0.5

    return max(1, int((total_distance / 20.0) * 1000.0))