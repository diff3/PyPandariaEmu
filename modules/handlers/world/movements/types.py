#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Immutable movement data types.

Templates are shared cached data. Instances are lightweight runtime handles.
Evaluation must return a new transform and must not mutate either object.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class InterpolationMode(str, Enum):
    LINEAR = "LINEAR"
    SPLINE = "SPLINE"

class MovementKind(str, Enum):
    TRANSPORT = "transport"
    ELEVATOR = "elevator"
    TRAM = "tram"
    TAXI = "taxi"


class MovementLifecycleEventType(str, Enum):
    SPAWN = "SPAWN"
    DESPAWN = "DESPAWN"
    ARRIVED = "ARRIVED"
    DEPARTED = "DEPARTED"
    TRANSFER_BEGIN = "TRANSFER_BEGIN"
    TRANSFER_COMPLETE = "TRANSFER_COMPLETE"


class MovementVisibilityState(str, Enum):
    ACTIVE = "ACTIVE"
    WAITING = "WAITING"
    DESPAWNED = "DESPAWNED"
    TRANSFERRING = "TRANSFERRING"


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
    interpolation_mode: InterpolationMode = InterpolationMode.SPLINE
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
class PassengerAttachment:
    passenger_id: int
    local_x: float = 0.0
    local_y: float = 0.0
    local_z: float = 0.0
    local_o: float = 0.0
    source_map: int = 0
    attached_at_ms: int = 0


@dataclass(frozen=True)
class PassengerTransferState:
    passenger_id: int
    source_instance_id: int
    destination_instance_id: int
    target_map_id: int
    local_x: float = 0.0
    local_y: float = 0.0
    local_z: float = 0.0
    local_o: float = 0.0
    started_at_ms: int = 0


@dataclass(frozen=True)
class MovementLifecycleEvent:
    event_type: MovementLifecycleEventType
    instance_id: int
    phase_ms: int
    node_index: int
    target_map_id: int | None = None
    message: str = ""


@dataclass
class MovementRuntimeState:
    instance: MovementInstance
    lifecycle_state: str = "ACTIVE"
    previous_lifecycle_state: str = ""
    visibility_state: str = MovementVisibilityState.ACTIVE.value
    previous_visibility_state: str = ""
    last_event: str = ""
    last_phase_ms: int = -1
    transfer_destination_map: int | None = None
    evaluated_transform: "MovementTransform | None" = None
    lifecycle_events: tuple[MovementLifecycleEvent, ...] = ()
    last_node_index: int = -1
    transfer_active: bool = False
    spawned: bool = False
    passengers: dict[int, PassengerAttachment] | None = None
    pending_transfers: dict[int, PassengerTransferState] | None = None


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
