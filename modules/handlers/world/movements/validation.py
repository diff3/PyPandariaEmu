#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Validation helpers for movement templates."""

from __future__ import annotations

from .types import MovementNode, MovementTemplate


def validate_nodes(nodes: tuple[MovementNode, ...]) -> tuple[bool, str]:
    if len(nodes) < 2:
        return False, "node count < 2"

    previous_time = -1
    for index, node in enumerate(nodes):
        if int(node.map_id) < 0:
            return False, f"node {index} has invalid map"
        if int(node.time_ms) < 0:
            return False, f"node {index} has negative time"
        if int(node.time_ms) < previous_time:
            return False, f"node {index} time is not monotonic"
        previous_time = int(node.time_ms)
    return True, ""


def validate_template(template: MovementTemplate) -> tuple[bool, str]:
    valid, reason = validate_nodes(template.nodes)
    if not valid:
        return False, reason
    if int(template.period_ms) <= 0:
        return False, "period <= 0"
    if not template.arc_lengths:
        return False, "missing arc-length table"
    return True, ""
