#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Template builders for DBC-backed movement data."""

from __future__ import annotations

from .interpolation import build_arc_lengths
from .types import MovementKind, MovementNode, MovementTemplate
from .validation import validate_template


def build_template(
    template_id: str,
    kind: MovementKind,
    nodes: tuple[MovementNode, ...],
    *,
    period_ms: int | None = None,
) -> tuple[MovementTemplate | None, str]:
    if len(nodes) < 2:
        return None, "node count < 2"

    resolved_period = int(period_ms or max(int(node.time_ms) for node in nodes) or 0)
    if resolved_period <= 0:
        resolved_period = _period_from_node_distances(nodes)

    transfer_nodes = tuple(
        index
        for index, node in enumerate(nodes[:-1])
        if int(node.map_id) != int(nodes[index + 1].map_id) or bool(node.transfer)
    )
    station_nodes = tuple(index for index, node in enumerate(nodes) if bool(node.station))
    template = MovementTemplate(
        template_id=str(template_id),
        kind=kind,
        nodes=tuple(nodes),
        period_ms=int(resolved_period),
        arc_lengths=build_arc_lengths(tuple(nodes)),
        total_length=0.0,
        transfer_nodes=transfer_nodes,
        station_nodes=station_nodes,
    )
    total_length = float(template.arc_lengths[-1].distance) if template.arc_lengths else 0.0
    template = MovementTemplate(
        template_id=template.template_id,
        kind=template.kind,
        nodes=template.nodes,
        period_ms=template.period_ms,
        arc_lengths=template.arc_lengths,
        total_length=total_length,
        transfer_nodes=template.transfer_nodes,
        station_nodes=template.station_nodes,
    )
    valid, reason = validate_template(template)
    if not valid:
        return None, reason
    return template, ""


def _period_from_node_distances(nodes: tuple[MovementNode, ...]) -> int:
    distance = 0.0
    for current, target in zip(nodes, nodes[1:]):
        if int(current.map_id) != int(target.map_id):
            continue
        dx = float(target.x) - float(current.x)
        dy = float(target.y) - float(current.y)
        dz = float(target.z) - float(current.z)
        distance += ((dx * dx) + (dy * dy) + (dz * dz)) ** 0.5
    return max(1, int(distance / 20.0 * 1000.0))
