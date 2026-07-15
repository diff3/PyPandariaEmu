#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Canonical publication boundary for a player's absolute world position."""

from __future__ import annotations

import math
from dataclasses import dataclass, replace
from typing import Any


@dataclass(frozen=True)
class AbsolutePlayerPosition:
    map_id: int
    instance_id: int
    x: float
    y: float
    z: float
    orientation: float


def _movement_state(session: Any):
    state = getattr(session, "movement_state", None)
    if state is None:
        from server.session.world_session import MovementState

        state = MovementState()
        session.movement_state = state
    return state


def _publish(
    session: Any,
    position: AbsolutePlayerPosition,
    *,
    synchronize_membership: bool,
    resolve_area: bool,
    capture_persistence: bool,
) -> AbsolutePlayerPosition:
    """Commit one absolute position to every passive runtime representation."""
    state = _movement_state(session)
    state.x = float(position.x)
    state.y = float(position.y)
    state.z = float(position.z)
    state.orientation = float(position.orientation)

    session.map_id = int(position.map_id)
    session.instance_id = int(position.instance_id)
    session.x = float(position.x)
    session.y = float(position.y)
    session.z = float(position.z)
    session.orientation = float(position.orientation)

    from server.modules.handlers.world.runtime.player_store import (
        get_player_runtime_store,
    )

    player = get_player_runtime_store().get(
        int(getattr(session, "char_guid", 0) or 0)
    )
    if player is not None:
        player.map_id = int(position.map_id)
        player.instance_id = int(position.instance_id)
        player.x = float(position.x)
        player.y = float(position.y)
        player.z = float(position.z)
        player.orientation = float(position.orientation)

    if resolve_area:
        from server.modules.handlers.world.position.area_service import (
            resolve_area_from_position,
            resolve_zone_from_position,
        )

        zone = int(
            resolve_zone_from_position(position.map_id, position.x, position.y)
            or 0
        )
        area = int(
            resolve_area_from_position(position.map_id, position.x, position.y)
            or 0
        )
        if zone:
            session.zone = zone
        if area:
            session.current_area = area

    if capture_persistence:
        session.persist_map_id = int(position.map_id)
        session.persist_instance_id = int(position.instance_id)
        session.persist_x = float(position.x)
        session.persist_y = float(position.y)
        session.persist_z = float(position.z)
        session.persist_orientation = float(position.orientation)
        if resolve_area:
            session.persist_zone = int(
                getattr(session, "zone", 0)
                or getattr(session, "persist_zone", 0)
                or 0
            )

    if synchronize_membership:
        from server.modules.handlers.world.state.runtime import (
            attach_session_to_world_state,
        )

        attach_session_to_world_state(session, map_id=int(position.map_id))

    return position


def publish_absolute(
    session: Any,
    *,
    map_id: int,
    instance_id: int,
    x: float,
    y: float,
    z: float,
    orientation: float,
    synchronize_membership: bool = False,
    resolve_area: bool = False,
    capture_persistence: bool = False,
) -> AbsolutePlayerPosition:
    return _publish(
        session,
        AbsolutePlayerPosition(
            map_id=int(map_id),
            instance_id=int(instance_id),
            x=float(x),
            y=float(y),
            z=float(z),
            orientation=float(orientation),
        ),
        synchronize_membership=bool(synchronize_membership),
        resolve_area=bool(resolve_area),
        capture_persistence=bool(capture_persistence),
    )


def publish_from_movement(
    session: Any,
    *,
    x: float,
    y: float,
    z: float,
    orientation: float,
) -> AbsolutePlayerPosition:
    return publish_absolute(
        session,
        map_id=int(getattr(session, "map_id", 0) or 0),
        instance_id=int(getattr(session, "instance_id", 0) or 0),
        x=x,
        y=y,
        z=z,
        orientation=orientation,
    )


def publish_from_teleport(
    session: Any,
    *,
    map_id: int,
    instance_id: int,
    x: float,
    y: float,
    z: float,
    orientation: float,
    synchronize_membership: bool = True,
    resolve_area: bool = True,
    capture_persistence: bool = True,
) -> AbsolutePlayerPosition:
    return publish_absolute(
        session,
        map_id=map_id,
        instance_id=instance_id,
        x=x,
        y=y,
        z=z,
        orientation=orientation,
        synchronize_membership=synchronize_membership,
        resolve_area=resolve_area,
        capture_persistence=capture_persistence,
    )


def publish_transport(
    session: Any,
    transport_state: Any,
    attachment: Any,
    *,
    synchronize_membership: bool = False,
    resolve_area: bool = False,
    capture_persistence: bool = False,
) -> AbsolutePlayerPosition:
    """Project one canonical passenger attachment into absolute coordinates."""
    transport_o = float(getattr(transport_state, "orientation", 0.0) or 0.0)
    local_x = float(getattr(attachment, "local_x", 0.0) or 0.0)
    local_y = float(getattr(attachment, "local_y", 0.0) or 0.0)
    cos_o = math.cos(transport_o)
    sin_o = math.sin(transport_o)
    absolute_o = math.fmod(
        transport_o + float(getattr(attachment, "local_o", 0.0) or 0.0),
        math.tau,
    )
    if absolute_o < 0.0:
        absolute_o += math.tau
    return publish_absolute(
        session,
        map_id=int(getattr(transport_state, "map_id", 0) or 0),
        instance_id=int(getattr(session, "instance_id", 0) or 0),
        x=float(getattr(transport_state, "x", 0.0) or 0.0)
        + cos_o * local_x
        - sin_o * local_y,
        y=float(getattr(transport_state, "y", 0.0) or 0.0)
        + sin_o * local_x
        + cos_o * local_y,
        z=float(getattr(transport_state, "z", 0.0) or 0.0)
        + float(getattr(attachment, "local_z", 0.0) or 0.0),
        orientation=absolute_o,
        synchronize_membership=synchronize_membership,
        resolve_area=resolve_area,
        capture_persistence=capture_persistence,
    )


def publish_transport_local_offset(
    session: Any,
    transport_state: Any,
    attachment: Any,
    *,
    local_x: float,
    local_y: float,
    local_z: float,
    local_o: float,
    transport_time: int | None = None,
    transport_time2: int = 0,
    transport_time3: int = 0,
    seat: int = -1,
    vehicle_id: int = 0,
):
    """Replace the immutable attachment and mirror it into MovementState."""
    updated = replace(
        attachment,
        local_x=float(local_x),
        local_y=float(local_y),
        local_z=float(local_z),
        local_o=float(local_o),
    )
    passengers = getattr(transport_state, "passengers", None)
    if not isinstance(passengers, dict):
        raise ValueError("RuntimeTransportState has no canonical passenger registry")
    passenger_id = int(getattr(updated, "passenger_id", 0) or 0)
    if passengers.get(passenger_id) is not attachment:
        raise ValueError("PassengerAttachment is not owned by RuntimeTransportState")
    passengers[passenger_id] = updated

    movement = _movement_state(session)
    movement.has_transport_data = True
    movement.transport_guid = int(getattr(transport_state, "guid", 0) or 0)
    movement.transport_x = float(local_x)
    movement.transport_y = float(local_y)
    movement.transport_z = float(local_z)
    movement.transport_orientation = float(local_o)
    movement.transport_o = float(local_o)
    movement.transport_time = int(
        getattr(transport_state, "path_progress_ms", 0)
        if transport_time is None
        else transport_time
    ) & 0xFFFFFFFF
    movement.transport_time2 = int(transport_time2) & 0xFFFFFFFF
    movement.transport_time3 = int(transport_time3) & 0xFFFFFFFF
    movement.transport_seat = int(seat)
    movement.transport_vehicle_id = int(vehicle_id)
    return updated


def publish_transport_local_from_absolute(
    session: Any,
    transport_state: Any,
    attachment: Any,
):
    """Inverse-project the current player transform into transport-local space."""
    current = publish_absolute(
        session,
        map_id=int(getattr(session, "map_id", getattr(transport_state, "map_id", 0)) or 0),
        instance_id=int(getattr(session, "instance_id", 0) or 0),
        x=float(getattr(session, "x", 0.0) or 0.0),
        y=float(getattr(session, "y", 0.0) or 0.0),
        z=float(getattr(session, "z", 0.0) or 0.0),
        orientation=float(getattr(session, "orientation", 0.0) or 0.0),
    )
    transport_x = float(getattr(transport_state, "x", 0.0) or 0.0)
    transport_y = float(getattr(transport_state, "y", 0.0) or 0.0)
    transport_z = float(getattr(transport_state, "z", 0.0) or 0.0)
    transport_o = float(getattr(transport_state, "orientation", 0.0) or 0.0)
    delta_x = current.x - transport_x
    delta_y = current.y - transport_y
    cos_o = math.cos(transport_o)
    sin_o = math.sin(transport_o)
    local_x = cos_o * delta_x + sin_o * delta_y
    local_y = -sin_o * delta_x + cos_o * delta_y
    local_z = current.z - transport_z
    local_o = math.fmod(
        current.orientation - transport_o,
        math.tau,
    )
    if local_o < 0.0:
        local_o += math.tau

    movement = _movement_state(session)
    return publish_transport_local_offset(
        session,
        transport_state,
        attachment,
        local_x=local_x,
        local_y=local_y,
        local_z=local_z,
        local_o=local_o,
        transport_time=int(getattr(movement, "transport_time", 0) or 0),
        transport_time2=int(getattr(movement, "transport_time2", 0) or 0),
        transport_time3=int(getattr(movement, "transport_time3", 0) or 0),
        seat=int(getattr(movement, "transport_seat", -1)),
        vehicle_id=int(getattr(movement, "transport_vehicle_id", 0) or 0),
    )
