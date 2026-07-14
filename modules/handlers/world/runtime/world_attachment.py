#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Persistence boundary for login-time moving WorldObject attachment."""

from __future__ import annotations

import math
from typing import Any

from shared.Logger import Logger


_MAX_SAVED_OFFSET = 900.0


def _saved_offset_is_valid(values: tuple[float, float, float, float]) -> bool:
    local_x, local_y, local_z, local_o = values
    return (
        all(math.isfinite(value) for value in values)
        and math.sqrt(
            local_x * local_x
            + local_y * local_y
            + local_z * local_z
        ) <= _MAX_SAVED_OFFSET
        and abs(local_o) <= math.tau * 4.0
    )


def load_saved_world_attachment(session: Any, row: Any) -> bool:
    """Load persisted identity and offsets without attaching the player yet."""
    spawn_id = int(getattr(row, "transguid", 0) or 0)
    if spawn_id <= 0:
        session.pending_world_attachment_restore = None
        return False
    session.pending_world_attachment_restore = {
        "spawn_id": spawn_id,
        "local_x": float(getattr(row, "trans_x", 0.0) or 0.0),
        "local_y": float(getattr(row, "trans_y", 0.0) or 0.0),
        "local_z": float(getattr(row, "trans_z", 0.0) or 0.0),
        "local_o": float(getattr(row, "trans_o", 0.0) or 0.0),
        "safe_map": int(getattr(session, "map_id", 0) or 0),
        "safe_instance_id": int(getattr(session, "instance_id", 0) or 0),
        "safe_x": float(getattr(session, "x", 0.0) or 0.0),
        "safe_y": float(getattr(session, "y", 0.0) or 0.0),
        "safe_z": float(getattr(session, "z", 0.0) or 0.0),
        "safe_o": float(getattr(session, "orientation", 0.0) or 0.0),
        "status": "LOADED",
    }
    return True


def _clear_persisted_attachment(session: Any) -> None:
    try:
        from server.modules.database.DatabaseConnection import DatabaseConnection

        DatabaseConnection.save_character_world_attachment(
            int(getattr(session, "char_guid", 0) or 0),
            int(getattr(session, "realm_id", 0) or 0),
            spawn_id=0,
            local_x=0.0,
            local_y=0.0,
            local_z=0.0,
            local_o=0.0,
        )
    except Exception as exc:
        Logger.warning(
            "[WorldAttachment] persisted clear failed player=%s error=%s",
            int(getattr(session, "char_guid", 0) or 0),
            str(exc),
        )


def _clear_runtime_attachment(session: Any) -> None:
    from server.modules.handlers.world.transport_runtime import (
        ATTACH_STATE_DETACHED,
        detach_session_transport_passenger,
    )

    detach_session_transport_passenger(
        session,
        reason="login_attachment_restore",
        opcode_name="login_bootstrap",
    )
    movement = getattr(session, "movement_state", None)
    if movement is not None:
        movement.has_transport_data = False
        movement.transport_guid = 0
        movement.transport_x = 0.0
        movement.transport_y = 0.0
        movement.transport_z = 0.0
        movement.transport_orientation = 0.0
        movement.transport_o = 0.0
        movement.transport_time = 0
        movement.transport_time2 = 0
        movement.transport_time3 = 0
        movement.transport_seat = -1
        movement.transport_vehicle_id = 0
    session.transport_attach_state = ATTACH_STATE_DETACHED
    session.transport_attached_guid = 0
    session.transport_attach_source_map = 0
    session._player_bootstrap_runtime_transport = None


def _restore_safe_position(session: Any, pending: dict[str, Any]) -> None:
    session.map_id = int(pending.get("safe_map", 0) or 0)
    session.instance_id = int(pending.get("safe_instance_id", 0) or 0)
    session.x = float(pending.get("safe_x", 0.0) or 0.0)
    session.y = float(pending.get("safe_y", 0.0) or 0.0)
    session.z = float(pending.get("safe_z", 0.0) or 0.0)
    session.orientation = float(pending.get("safe_o", 0.0) or 0.0)
    if (
        getattr(session, "region", None) is not None
        or getattr(session, "global_state", None) is not None
    ):
        from server.modules.handlers.world.state.runtime import (
            attach_session_to_world_state,
        )

        attach_session_to_world_state(session, map_id=int(session.map_id))


def abort_login_world_attachment(
    session: Any,
    *,
    reason: str,
    clear_persisted: bool = True,
) -> bool:
    """Detach a prepared login restore and return to its safe position."""
    pending = getattr(session, "pending_world_attachment_restore", None)
    if not isinstance(pending, dict):
        return False
    _clear_runtime_attachment(session)
    _restore_safe_position(session, pending)
    session.pending_world_attachment_restore = None
    if clear_persisted:
        _clear_persisted_attachment(session)
    Logger.warning(
        "[WorldAttachment] restore rejected player=%s spawn=%s reason=%s",
        int(getattr(session, "char_guid", 0) or 0),
        int(pending.get("spawn_id", 0) or 0),
        str(reason),
    )
    return True


def prepare_login_world_attachment(session: Any) -> bool:
    """Resolve and attach one saved moving WorldObject for login bootstrap."""
    pending = getattr(session, "pending_world_attachment_restore", None)
    if not isinstance(pending, dict):
        return False

    from server.modules.handlers.world.transport_runtime import (
        ATTACH_STATE_ATTACHED,
        TRANSPORT_STATE_ACTIVE,
        attach_transport_passenger,
        get_world_transport_manager,
    )

    resolved = get_world_transport_manager().resolve_world_object_by_spawn_id(
        int(pending.get("spawn_id", 0) or 0)
    )
    if resolved is None:
        abort_login_world_attachment(session, reason="runtime_object_missing")
        return False
    world_object, runtime_state = resolved
    lifecycle_state = str(
        getattr(runtime_state, "lifecycle_state", "") or ""
    )
    if (
        lifecycle_state != TRANSPORT_STATE_ACTIVE
        or bool(getattr(runtime_state, "transfer_active", False))
    ):
        abort_login_world_attachment(session, reason="runtime_object_transferring")
        return False
    if (
        int(world_object.runtime_guid)
        != int(getattr(runtime_state, "guid", 0) or 0)
        or int(world_object.map_id)
        != int(getattr(runtime_state, "map_id", -1))
    ):
        abort_login_world_attachment(session, reason="runtime_identity_mismatch")
        return False
    if int(world_object.instance_id) != int(
        pending.get("safe_instance_id", 0) or 0
    ):
        abort_login_world_attachment(session, reason="instance_mismatch")
        return False

    local_offset = (
        float(pending.get("local_x", 0.0) or 0.0),
        float(pending.get("local_y", 0.0) or 0.0),
        float(pending.get("local_z", 0.0) or 0.0),
        float(pending.get("local_o", 0.0) or 0.0),
    )
    if not _saved_offset_is_valid(local_offset):
        abort_login_world_attachment(session, reason="invalid_offset")
        return False

    local_x, local_y, local_z, local_o = local_offset
    cos_o = math.cos(float(world_object.orientation))
    sin_o = math.sin(float(world_object.orientation))
    rotated_x = cos_o * local_x - sin_o * local_y
    rotated_y = sin_o * local_x + cos_o * local_y
    runtime_guid = int(world_object.runtime_guid)
    previous_map_id = int(getattr(session, "map_id", 0) or 0)
    session.map_id = int(world_object.map_id)
    session.instance_id = int(world_object.instance_id)
    session.x = float(world_object.x) + rotated_x
    session.y = float(world_object.y) + rotated_y
    session.z = float(world_object.z) + local_z
    session.orientation = float(world_object.orientation) + local_o
    if (
        previous_map_id != int(session.map_id)
        and (
            getattr(session, "region", None) is not None
            or getattr(session, "global_state", None) is not None
        )
    ):
        from server.modules.handlers.world.state.runtime import (
            attach_session_to_world_state,
        )

        attach_session_to_world_state(session, map_id=int(session.map_id))

    movement = getattr(session, "movement_state", None)
    if movement is None:
        from server.session.world_session import MovementState

        movement = MovementState()
        session.movement_state = movement
    movement.has_transport_data = True
    movement.transport_guid = runtime_guid
    movement.transport_x = local_x
    movement.transport_y = local_y
    movement.transport_z = local_z
    movement.transport_orientation = local_o
    movement.transport_time = int(
        getattr(runtime_state, "path_progress_ms", 0) or 0
    ) & 0xFFFFFFFF
    movement.transport_time2 = 0
    movement.transport_time3 = 0
    movement.transport_seat = -1
    movement.transport_vehicle_id = 0

    attached = attach_transport_passenger(
        runtime_guid,
        int(getattr(session, "char_guid", 0) or 0),
        local_x=local_x,
        local_y=local_y,
        local_z=local_z,
        local_o=local_o,
        source_map=int(world_object.map_id),
    )
    if not attached:
        abort_login_world_attachment(
            session,
            reason="passenger_registration_failed",
        )
        return False
    session.transport_attach_state = ATTACH_STATE_ATTACHED
    session.transport_attached_guid = runtime_guid
    session.transport_attach_source_map = int(world_object.map_id)
    pending["status"] = "PREPARED"
    pending["runtime_guid"] = runtime_guid
    session._player_bootstrap_runtime_transport = {
        "transport_guid": runtime_guid,
        "map_id": int(world_object.map_id),
        "x": float(world_object.x),
        "y": float(world_object.y),
        "z": float(world_object.z),
        "orientation": float(world_object.orientation),
        "route_phase": int(
            getattr(runtime_state, "path_progress_ms", 0) or 0
        ) & 0xFFFFFFFF,
        "local_x": local_x,
        "local_y": local_y,
        "local_z": local_z,
        "local_o": local_o,
        "rotated_x": rotated_x,
        "rotated_y": rotated_y,
        "rotated_z": local_z,
        "transport_create_transform_matched": False,
    }
    Logger.info(
        "[WorldAttachment] restore prepared player=%s spawn=%s runtime=0x%016X",
        int(getattr(session, "char_guid", 0) or 0),
        int(pending.get("spawn_id", 0) or 0),
        runtime_guid & 0xFFFFFFFFFFFFFFFF,
    )
    return True


def complete_login_world_attachment(session: Any) -> bool:
    """Commit a prepared attachment at the active-mover bootstrap boundary."""
    pending = getattr(session, "pending_world_attachment_restore", None)
    if not isinstance(pending, dict) or pending.get("status") != "PREPARED":
        return False
    session.pending_world_attachment_restore = None
    Logger.info(
        "[WorldAttachment] restore completed player=%s runtime=0x%016X",
        int(getattr(session, "char_guid", 0) or 0),
        int(pending.get("runtime_guid", 0) or 0) & 0xFFFFFFFFFFFFFFFF,
    )
    return True


def persist_session_world_attachment(
    session: Any,
    *,
    db_api: Any | None = None,
) -> bool:
    """Persist stable spawn identity and local offsets for the next login."""
    if db_api is None:
        from server.modules.database.DatabaseConnection import DatabaseConnection

        db_api = DatabaseConnection

    spawn_id = 0
    local_x = local_y = local_z = local_o = 0.0
    movement = getattr(session, "movement_state", None)
    runtime_guid = int(getattr(movement, "transport_guid", 0) or 0)
    if (
        str(getattr(session, "transport_attach_state", "") or "")
        == "ATTACHED"
        and bool(getattr(movement, "has_transport_data", False))
        and runtime_guid > 0
    ):
        from server.modules.handlers.world.transport_runtime import (
            get_world_transport_manager,
        )

        state = get_world_transport_manager().state_for_guid(runtime_guid)
        if (
            state is not None
            and not bool(getattr(state, "transfer_active", False))
        ):
            spawn_id = int(getattr(state, "spawn_guid", 0) or 0)
            local_x = float(getattr(movement, "transport_x", 0.0) or 0.0)
            local_y = float(getattr(movement, "transport_y", 0.0) or 0.0)
            local_z = float(getattr(movement, "transport_z", 0.0) or 0.0)
            local_o = float(
                getattr(movement, "transport_orientation", 0.0) or 0.0
            )
            if not _saved_offset_is_valid(
                (local_x, local_y, local_z, local_o)
            ):
                spawn_id = 0
                local_x = local_y = local_z = local_o = 0.0

    saved = bool(
        db_api.save_character_world_attachment(
            int(getattr(session, "char_guid", 0) or 0),
            int(getattr(session, "realm_id", 0) or 0),
            spawn_id=spawn_id,
            local_x=local_x,
            local_y=local_y,
            local_z=local_z,
            local_o=local_o,
        )
    )
    return saved
