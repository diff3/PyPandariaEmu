#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Immutable movement data types.

Templates are shared cached data. Instances are lightweight runtime handles.
Evaluation must return a new transform and must not mutate either object.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class MovementKind(str, Enum):
    TRANSPORT = "transport"
    ELEVATOR = "elevator"
    TRAM = "tram"
    TAXI = "taxi"


@dataclass(frozen=True)
class MovementNode:
    map_id: int
    x: float
    y: float
    z: float
    time_ms: int = 0
    yaw: float | None = None
    station: bool = False
    transfer: bool = False


@dataclass(frozen=True)
class ArcLengthSample:
    node_index: int
    t: float
    distance: float
    map_id: int
    x: float
    y: float
    z: float


@dataclass(frozen=True)
class MovementTemplate:
    template_id: str
    kind: MovementKind
    nodes: tuple[MovementNode, ...]
    period_ms: int
    arc_lengths: tuple[ArcLengthSample, ...]
    total_length: float
    transfer_nodes: tuple[int, ...] = ()
    station_nodes: tuple[int, ...] = ()


@dataclass(frozen=True)
class MovementInstance:
    instance_id: int
    template_id: str
    started_at_ms: int = 0
    phase_offset_ms: int = 0
    active: bool = True


@dataclass(frozen=True)
class MovementTransform:
    map_id: int
    x: float
    y: float
    z: float
    orientation: float
    phase_ms: int
    node_index: int
    next_node_index: int
    state: str
    event: str = ""
