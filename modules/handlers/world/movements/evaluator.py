#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Pure deterministic movement evaluation."""

from __future__ import annotations

from .interpolation import heading_from_delta, sample_by_distance
from .types import MovementTemplate, MovementTransform


STATE_ACTIVE = "ACTIVE"
STATE_DOCKED = "DOCKED"
STATE_TRANSFER_PENDING = "TRANSFER_PENDING"


def evaluate_template(template: MovementTemplate, server_time_ms: int, *, phase_offset_ms: int = 0) -> MovementTransform:
    period = max(1, int(template.period_ms))
    phase = (int(server_time_ms) + int(phase_offset_ms)) % period
    node_index, next_index, segment_ratio = _segment_for_phase(template, phase)
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

    if template.total_length > 0.0:
        target_distance = float(template.total_length) * (float(phase) / float(period))
        sample = sample_by_distance(template.arc_lengths, target_distance)
        ahead = sample_by_distance(template.arc_lengths, min(template.total_length, target_distance + 1.0))
        orientation = heading_from_delta(float(ahead.x) - float(sample.x), float(ahead.y) - float(sample.y), float(node.yaw or 0.0))
        return MovementTransform(
            map_id=int(sample.map_id),
            x=float(sample.x),
            y=float(sample.y),
            z=float(sample.z),
            orientation=orientation,
            phase_ms=int(phase),
            node_index=int(node_index),
            next_node_index=int(next_index),
            state=state,
            event=event,
        )

    x = float(node.x) + ((float(next_node.x) - float(node.x)) * segment_ratio)
    y = float(node.y) + ((float(next_node.y) - float(node.y)) * segment_ratio)
    z = float(node.z) + ((float(next_node.z) - float(node.z)) * segment_ratio)
    orientation = heading_from_delta(float(next_node.x) - float(node.x), float(next_node.y) - float(node.y), float(node.yaw or 0.0))
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


def _segment_for_phase(template: MovementTemplate, phase_ms: int) -> tuple[int, int, float]:
    nodes = template.nodes
    if len(nodes) < 2:
        return 0, 0, 0.0

    for index in range(len(nodes) - 1):
        start = int(nodes[index].time_ms)
        end = int(nodes[index + 1].time_ms)
        if start <= int(phase_ms) <= end:
            duration = max(1, end - start)
            return index, index + 1, max(0.0, min(1.0, (int(phase_ms) - start) / duration))
    return len(nodes) - 1, 0, 1.0
