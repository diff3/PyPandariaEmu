#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Pure deterministic movement evaluation."""

from __future__ import annotations

from .interpolation import heading_from_delta, sample_by_distance
from .types import (
    InterpolationMode,
    MovementTemplate,
    MovementTransform,
)

import math


STATE_ACTIVE = "ACTIVE"
STATE_DOCKED = "DOCKED"
STATE_TRANSFER_PENDING = "TRANSFER_PENDING"


def evaluate_template(
    template: MovementTemplate,
    server_time_ms: int,
    *,
    phase_offset_ms: int = 0,
) -> MovementTransform:
    """Evaluate immutable movement template."""

    period = max(1, int(template.period_ms))
    phase = (
        int(server_time_ms)
        + int(phase_offset_ms)
        - 11500
    ) % period
    node_index, next_index, segment_ratio = _segment_for_phase(
        template,
        phase,
    )

    node = template.nodes[node_index]
    next_node = template.nodes[next_index]

    event = ""
    state = STATE_ACTIVE

    if int(node.map_id) != int(next_node.map_id):
        event = "transfer"
        state = STATE_TRANSFER_PENDING

        return MovementTransform(
            map_id=int(node.map_id),
            x=float(node.x),
            y=float(node.y),
            z=float(node.z),
            orientation=float(node.yaw or 0.0),
            phase_ms=int(phase),
            node_index=int(node_index),
            next_node_index=int(next_index),
            state=state,
            event=event,
        )

    if node_index in template.station_nodes:
        state = STATE_DOCKED
        event = "station"
        return MovementTransform(
            map_id=int(node.map_id),
            x=float(node.x),
            y=float(node.y),
            z=float(node.z),
            orientation=float(node.yaw or 0.0),
            phase_ms=int(phase),
            node_index=int(node_index),
            next_node_index=int(next_index),
            state=state,
            event=event,
        )

    if template.interpolation_mode == InterpolationMode.SPLINE:
        return _evaluate_spline(
            template,
            phase,
            period,
            node_index,
            next_index,
            state,
            event,
            node,
        )

    return _evaluate_linear(
        template,
        phase,
        node_index,
        next_index,
        segment_ratio,
        state,
        event,
        node,
        next_node,
    )


def _smooth_angle(
    current: float,
    target: float,
    factor: float,
) -> float:
    #
    # Shortest angular delta.
    #
    delta = (
        (target - current + math.pi)
        % (math.pi * 2.0)
    ) - math.pi

    return current + (delta * factor)


def _distance_for_phase(
    template: MovementTemplate,
    phase_ms: int,
) -> float:
    """
    Resolve deterministic movement distance for phase.

    IMPORTANT:
    Station/wait nodes consume time without
    consuming movement distance.
    """

    node_index, next_index, ratio = _segment_for_phase(
        template,
        phase_ms,
    )

    start_distance = float(
        template.phase_distances[node_index]
    )

    end_distance = float(
        template.phase_distances[next_index]
    )

    #
    # Dock/wait segment.
    #
    if node_index in template.station_nodes:
        return start_distance

    #
    # Cross-map transfer segment.
    #
    if (
        int(template.nodes[node_index].map_id)
        != int(template.nodes[next_index].map_id)
    ):
        return start_distance

    return start_distance + (
        (end_distance - start_distance)
        * float(ratio)
    )


def _evaluate_spline(
    template: MovementTemplate,
    phase: int,
    period: int,
    node_index: int,
    next_index: int,
    state: str,
    event: str,
    node,
) -> MovementTransform:
    """Evaluate spline-based movement."""

    target_distance = _distance_for_phase(
        template,
        phase,
    )

    sample = sample_by_distance(
        template.arc_lengths,
        target_distance,
    )

    lookahead = 14.0

    ahead_distance = min(
        template.total_length,
        target_distance + lookahead,
    )

    ahead = sample_by_distance(
        template.arc_lengths,
        ahead_distance,
    )

    target_orientation = heading_from_delta(
        float(ahead.x) - float(sample.x),
        float(ahead.y) - float(sample.y),
        float(node.yaw or 0.0),
    )

    orientation = _smooth_angle(
        float(node.yaw or target_orientation),
        target_orientation,
        0.10,
    )

    x = _stable_axis_value(
        template,
        "x",
        float(sample.x),
    )

    y = _stable_axis_value(
        template,
        "y",
        float(sample.y),
    )

    z = _stable_axis_value(
        template,
        "z",
        float(sample.z),
    )

    return MovementTransform(
        map_id=int(sample.map_id),
        x=x,
        y=y,
        z=z,
        orientation=orientation,
        phase_ms=int(phase),
        node_index=int(node_index),
        next_node_index=int(next_index),
        state=state,
        event=event,
    )


def _evaluate_linear(
    template: MovementTemplate,
    phase: int,
    node_index: int,
    next_index: int,
    segment_ratio: float,
    state: str,
    event: str,
    node,
    next_node,
) -> MovementTransform:
    """Evaluate linear node interpolation."""

    x = float(node.x) + (
        (float(next_node.x) - float(node.x))
        * float(segment_ratio)
    )

    y = float(node.y) + (
        (float(next_node.y) - float(node.y))
        * float(segment_ratio)
    )

    z = float(node.z) + (
        (float(next_node.z) - float(node.z))
        * float(segment_ratio)
    )

    orientation = heading_from_delta(
        float(next_node.x) - float(node.x),
        float(next_node.y) - float(node.y),
        float(node.yaw or 0.0),
    )

    return MovementTransform(
        map_id=int(node.map_id),
        x=x,
        y=y,
        z=z,
        orientation=orientation,
        phase_ms=int(phase),
        node_index=int(node_index),
        next_node_index=int(next_index),
        state=state,
        event=event,
    )


def _segment_for_phase(
    template: MovementTemplate,
    phase_ms: int,
) -> tuple[int, int, float]:
    """Resolve active segment for phase."""

    nodes = template.nodes

    if len(nodes) < 2:
        return 0, 0, 0.0

    for index in range(len(nodes) - 1):
        start = int(nodes[index].time_ms)
        end = int(nodes[index + 1].time_ms)

        if start <= int(phase_ms) < end:
            duration = max(1, end - start)

            ratio = (
                (int(phase_ms) - start)
                / duration
            )

            return (
                index,
                index + 1,
                max(0.0, min(1.0, ratio)),
            )

    return (
        len(nodes) - 2,
        len(nodes) - 1,
        1.0,
    )


def _stable_axis_value(
    template: MovementTemplate,
    axis: str,
    value: float,
) -> float:
    """Prevent drifting on fixed axes."""

    values = [
        float(getattr(node, axis))
        for node in template.nodes
    ]

    first = values[0]

    if all(
        abs(current - first) <= 0.000001
        for current in values
    ):
        return first

    return float(value)
