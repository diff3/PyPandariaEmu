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

    expanded_nodes = tuple(nodes)
    if kind != MovementKind.TAXI:
        expanded_nodes = _expand_wait_nodes(expanded_nodes)

    resolved_period = _resolve_period_ms(expanded_nodes, period_ms)

    transfer_nodes = _transfer_nodes(expanded_nodes)
    station_nodes = _station_nodes(expanded_nodes)

    arc_lengths = build_arc_lengths(
        expanded_nodes,
        interpolation_mode=interpolation_mode,
    )

    total_length = 0.0

    if arc_lengths:
        total_length = float(arc_lengths[-1].distance)

    #
    # Build deterministic phase->distance mapping.
    #
    # IMPORTANT:
    # Station/wait nodes consume TIME but do NOT consume DISTANCE.
    #
    # This prevents transports from visually drifting while docked.
    #
    phase_distances = _build_phase_distances(
        nodes=expanded_nodes,
        station_nodes=station_nodes,
    )

    template = MovementTemplate(
        template_id=str(template_id),
        kind=kind,
        nodes=expanded_nodes,
        period_ms=int(resolved_period),
        interpolation_mode=interpolation_mode,
        arc_lengths=arc_lengths,
        total_length=total_length,
        transfer_nodes=transfer_nodes,
        station_nodes=station_nodes,
        phase_distances=phase_distances,
    )

    valid, reason = validate_template(template)

    if not valid:
        return None, reason

    return template, ""


def _expand_wait_nodes(
    nodes: tuple[MovementNode, ...],
) -> tuple[MovementNode, ...]:
    """Convert node delays into same-position zero-distance wait segments."""

    if len(nodes) < 2:
        return nodes

    expanded: list[MovementNode] = []
    accumulated_delay = 0

    for index, node in enumerate(nodes):
        adjusted = _copy_node_with_time(
            node,
            int(node.time_ms) + int(accumulated_delay),
        )
        expanded.append(adjusted)

        delay_ms = max(0, int(getattr(node, "delay", 0) or 0))
        if delay_ms <= 0:
            continue

        next_node = nodes[index + 1] if index + 1 < len(nodes) else None
        wait_end_time = int(adjusted.time_ms) + int(delay_ms)

        if (
            next_node is not None
            and _same_position(node, next_node)
            and int(next_node.time_ms) + int(accumulated_delay) >= wait_end_time
        ):
            continue

        expanded.append(
            MovementNode(
                map_id=int(adjusted.map_id),
                x=float(adjusted.x),
                y=float(adjusted.y),
                z=float(adjusted.z),
                time_ms=wait_end_time,
                yaw=adjusted.yaw,
                station=False,
                transfer=bool(adjusted.transfer),
                flags=int(adjusted.flags),
                delay=0,
            )
        )
        accumulated_delay += int(delay_ms)

    return tuple(expanded)


def _copy_node_with_time(node: MovementNode, time_ms: int) -> MovementNode:
    return MovementNode(
        map_id=int(node.map_id),
        x=float(node.x),
        y=float(node.y),
        z=float(node.z),
        time_ms=int(time_ms),
        yaw=node.yaw,
        station=bool(node.station),
        transfer=bool(node.transfer),
        flags=int(node.flags),
        delay=int(node.delay),
    )


def _same_position(a: MovementNode, b: MovementNode) -> bool:
    return bool(
        int(a.map_id) == int(b.map_id)
        and abs(float(a.x) - float(b.x)) <= 0.000001
        and abs(float(a.y) - float(b.y)) <= 0.000001
        and abs(float(a.z) - float(b.z)) <= 0.000001
    )


def _resolve_period_ms(
    nodes: tuple[MovementNode, ...],
    period_ms: int | None,
) -> int:
    """Resolve template period."""

    largest_node_time = max(
        int(node.time_ms)
        for node in nodes
    )

    if period_ms is not None and int(period_ms) > 0:
        return max(int(period_ms), int(largest_node_time))

    if largest_node_time > 0:
        return int(largest_node_time)

    return _period_from_node_distances(nodes)


def _transfer_nodes(
    nodes: tuple[MovementNode, ...],
) -> tuple[int, ...]:
    """Collect transfer nodes."""

    result: list[int] = []

    for index, node in enumerate(nodes[:-1]):
        next_node = nodes[index + 1]

        #
        # Cross-map transitions are transfer boundaries.
        #
        if int(node.map_id) != int(next_node.map_id):
            result.append(index)
            continue

        #
        # Explicit transfer node.
        #
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


def _build_phase_distances(
    *,
    nodes: tuple[MovementNode, ...],
    station_nodes: tuple[int, ...],
) -> tuple[float, ...]:
    """
    Build cumulative path distance per node phase.

    IMPORTANT:
    Station/wait nodes consume time without consuming distance.

    This allows:
    - deterministic docking
    - stable wait phases
    - no spline drift while docked
    """

    if not nodes:
        return tuple()

    station_set = set(
        int(index)
        for index in station_nodes
    )

    result: list[float] = [0.0]

    cumulative_distance = 0.0

    for index in range(len(nodes) - 1):
        current = nodes[index]
        target = nodes[index + 1]

        #
        # Cross-map transitions do not interpolate movement.
        #
        if int(current.map_id) != int(target.map_id):
            result.append(float(cumulative_distance))
            continue

        #
        # Dock/wait segment.
        #
        # Time advances but transport position remains fixed.
        #
        if index in station_set:
            result.append(float(cumulative_distance))
            continue

        dx = float(target.x) - float(current.x)
        dy = float(target.y) - float(current.y)
        dz = float(target.z) - float(current.z)

        segment_distance = (
            (dx * dx)
            + (dy * dy)
            + (dz * dz)
        ) ** 0.5

        cumulative_distance += float(segment_distance)

        result.append(float(cumulative_distance))

    return tuple(result)


def _period_from_node_distances(
    nodes: tuple[MovementNode, ...],
) -> int:
    """Estimate fallback movement period from path distance."""

    total_distance = 0.0

    for current, target in zip(nodes, nodes[1:]):
        #
        # Ignore cross-map transfer segments.
        #
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

    #
    # Fallback speed estimate:
    # ~20 yards/sec.
    #
    return max(
        1,
        int((total_distance / 20.0) * 1000.0),
    )
