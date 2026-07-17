#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import math
from typing import Any

from shared.ConfigLoader import ConfigLoader
from shared.Logger import Logger

CONFIG_ENABLE_ELEVATORS = "Transport.EnableElevators"
CONFIG_ENABLE_MOVING_TRANSPORTS = "Transport.EnableMovingTransports"
CONFIG_DEBUG_TRANSPORT_LIFECYCLE = "Transport.DebugLifecycle"
CONFIG_DEBUG_TRANSPORT_MOVEMENT = "Transport.DebugMovement"
CONFIG_DEBUG_TRANSPORT_PACKETS = "Transport.DebugPackets"
CONFIG_DEBUG_TRANSPORT_MESSAGES = "Transport.DebugMessages"
CONFIG_AUTONOMOUS_TRANSPORT_VISIBILITY = "Transport.AutonomousVisibility"
CONFIG_EXPERIMENTAL_PLAYER_CREATE_LIVING_MOVEMENT = "Transport.ExperimentalPlayerCreateLivingMovement"
CONFIG_TRANSPORT_ATTACHMENT_HORIZONTAL_TOLERANCE = "Transport.AttachmentHorizontalTolerance"
CONFIG_TRANSPORT_ATTACHMENT_VERTICAL_TOLERANCE = "Transport.AttachmentVerticalTolerance"
CONFIG_TRANSPORT_ATTACHMENT_MAX_LOCAL_RADIUS = "Transport.AttachmentMaxLocalRadius"
CONFIG_ENABLE_FLIGHT_PATHS = "Taxi.EnableFlightPaths"
CONFIG_DEBUG_TAXI_MOVEMENT = "Taxi.DebugMovement"
CONFIG_ENABLE_MAP_CHEAT = "Player.EnableMapExploreCheat"
CONFIG_ENABLE_TAXI_CHEAT = "Player.EnableTaxiCheat"
CONFIG_ENABLE_GAMEOBJECTS = "World.EnableGameObjects"
CONFIG_ENABLE_NPCS = "World.EnableNPCs"
CONFIG_ENABLE_NPC_AUTO_STREAM = "World.EnableNPCAutoStream"
CONFIG_DEBUG_NPC_ORIENTATION = "World.DebugNPCOrientation"
CONFIG_DEBUG_PLAYER_MOVEMENT = "World.DebugMovement"
DEFAULT_TRANSPORT_ATTACHMENT_HORIZONTAL_TOLERANCE = 25.0
DEFAULT_TRANSPORT_ATTACHMENT_VERTICAL_TOLERANCE = 12.0
DEFAULT_TRANSPORT_ATTACHMENT_MAX_LOCAL_RADIUS = 150.0

_DEFAULTS: dict[str, bool] = {
    CONFIG_ENABLE_ELEVATORS: True,
    CONFIG_ENABLE_MOVING_TRANSPORTS: True,
    CONFIG_DEBUG_TRANSPORT_LIFECYCLE: False,
    CONFIG_DEBUG_TRANSPORT_MOVEMENT: False,
    CONFIG_DEBUG_TRANSPORT_PACKETS: False,
    CONFIG_DEBUG_TRANSPORT_MESSAGES: False,
    CONFIG_AUTONOMOUS_TRANSPORT_VISIBILITY: False,
    CONFIG_EXPERIMENTAL_PLAYER_CREATE_LIVING_MOVEMENT: False,
    CONFIG_ENABLE_FLIGHT_PATHS: True,
    CONFIG_DEBUG_TAXI_MOVEMENT: False,
    CONFIG_ENABLE_MAP_CHEAT: False,
    CONFIG_ENABLE_TAXI_CHEAT: False,
    CONFIG_ENABLE_GAMEOBJECTS: True,
    CONFIG_ENABLE_NPCS: False,
    CONFIG_ENABLE_NPC_AUTO_STREAM: False,
    CONFIG_DEBUG_NPC_ORIENTATION: False,
    CONFIG_DEBUG_PLAYER_MOVEMENT: False,
}


def _coerce_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on", "enabled"}:
            return True
        if normalized in {"0", "false", "no", "off", "disabled"}:
            return False
    return bool(default)


def _lookup_key(config: dict[str, Any], dotted_key: str) -> Any:
    if dotted_key in config:
        return config[dotted_key]

    current: Any = config
    for part in dotted_key.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def feature_enabled(dotted_key: str) -> bool:
    default = bool(_DEFAULTS.get(str(dotted_key), False))
    config = ConfigLoader.get_config() or {}
    value = _lookup_key(config, str(dotted_key))
    if value is None:
        return default
    return _coerce_bool(value, default)


def elevators_enabled() -> bool:
    return feature_enabled(CONFIG_ENABLE_ELEVATORS)


def moving_transports_enabled() -> bool:
    return feature_enabled(CONFIG_ENABLE_MOVING_TRANSPORTS)


def transport_lifecycle_debug_enabled() -> bool:
    return feature_enabled(CONFIG_DEBUG_TRANSPORT_LIFECYCLE)


def transport_movement_debug_enabled() -> bool:
    return feature_enabled(CONFIG_DEBUG_TRANSPORT_MOVEMENT)


def transport_packet_debug_enabled() -> bool:
    return feature_enabled(CONFIG_DEBUG_TRANSPORT_PACKETS)


def transport_debug_messages_enabled() -> bool:
    return feature_enabled(CONFIG_DEBUG_TRANSPORT_MESSAGES)


def autonomous_transport_visibility_enabled() -> bool:
    return feature_enabled(CONFIG_AUTONOMOUS_TRANSPORT_VISIBILITY)


def experimental_player_create_living_movement_enabled() -> bool:
    return feature_enabled(CONFIG_EXPERIMENTAL_PLAYER_CREATE_LIVING_MOVEMENT)


def _positive_float_config(dotted_key: str, default: float) -> float:
    config = ConfigLoader.get_config() or {}
    value = _lookup_key(config, dotted_key)
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return float(default)
    return parsed if math.isfinite(parsed) and parsed > 0.0 else float(default)


def transport_attachment_geometry_tolerances() -> tuple[float, float, float]:
    return (
        _positive_float_config(
            CONFIG_TRANSPORT_ATTACHMENT_HORIZONTAL_TOLERANCE,
            DEFAULT_TRANSPORT_ATTACHMENT_HORIZONTAL_TOLERANCE,
        ),
        _positive_float_config(
            CONFIG_TRANSPORT_ATTACHMENT_VERTICAL_TOLERANCE,
            DEFAULT_TRANSPORT_ATTACHMENT_VERTICAL_TOLERANCE,
        ),
        _positive_float_config(
            CONFIG_TRANSPORT_ATTACHMENT_MAX_LOCAL_RADIUS,
            DEFAULT_TRANSPORT_ATTACHMENT_MAX_LOCAL_RADIUS,
        ),
    )


def flight_paths_enabled() -> bool:
    return feature_enabled(CONFIG_ENABLE_FLIGHT_PATHS)


def taxi_movement_debug_enabled() -> bool:
    return feature_enabled(CONFIG_DEBUG_TAXI_MOVEMENT)


def map_cheat_enabled() -> bool:
    return feature_enabled(CONFIG_ENABLE_MAP_CHEAT)


def taxi_cheat_enabled() -> bool:
    return feature_enabled(CONFIG_ENABLE_TAXI_CHEAT)


def gameobjects_enabled() -> bool:
    return feature_enabled(CONFIG_ENABLE_GAMEOBJECTS)


def npcs_enabled() -> bool:
    return feature_enabled(CONFIG_ENABLE_NPCS)


def npc_auto_stream_enabled() -> bool:
    return npcs_enabled() and feature_enabled(CONFIG_ENABLE_NPC_AUTO_STREAM)


def npc_orientation_debug_enabled() -> bool:
    return feature_enabled(CONFIG_DEBUG_NPC_ORIENTATION)


def player_movement_debug_enabled() -> bool:
    return feature_enabled(CONFIG_DEBUG_PLAYER_MOVEMENT)


def log_effective_world_feature_config() -> None:
    Logger.info("[Config] Elevators: %s", "enabled" if elevators_enabled() else "disabled")
    Logger.info("[Config] Moving transports: %s", "enabled" if moving_transports_enabled() else "disabled")
    Logger.info(
        "[Config] Transport lifecycle debug: %s",
        "enabled" if transport_lifecycle_debug_enabled() else "disabled",
    )
    Logger.info(
        "[Config] Transport movement debug: %s",
        "enabled" if transport_movement_debug_enabled() else "disabled",
    )
    Logger.info(
        "[Config] Transport packet debug: %s",
        "enabled" if transport_packet_debug_enabled() else "disabled",
    )
    Logger.info(
        "[Config] Transport debug messages: %s",
        "enabled" if transport_debug_messages_enabled() else "disabled",
    )
    Logger.info(
        "[Config] Autonomous transport visibility: %s",
        "enabled" if autonomous_transport_visibility_enabled() else "disabled",
    )
    Logger.info(
        "[Config] Experimental player CREATE living movement: %s",
        "enabled" if experimental_player_create_living_movement_enabled() else "disabled",
    )
    Logger.info("[Config] Flight paths: %s", "enabled" if flight_paths_enabled() else "disabled")
    Logger.info(
        "[Config] Taxi movement debug: %s",
        "enabled" if taxi_movement_debug_enabled() else "disabled",
    )
    Logger.info("[Config] Map cheat: %s", "enabled" if map_cheat_enabled() else "disabled")
    Logger.info("[Config] Taxi cheat: %s", "enabled" if taxi_cheat_enabled() else "disabled")
    Logger.info("[Config] GameObjects: %s", "enabled" if gameobjects_enabled() else "disabled")
    Logger.info("[Config] NPCs: %s", "enabled" if npcs_enabled() else "disabled")
    Logger.info("[Config] NPC auto stream: %s", "enabled" if npc_auto_stream_enabled() else "disabled")
    Logger.info(
        "[Config] NPC orientation debug: %s",
        "enabled" if npc_orientation_debug_enabled() else "disabled",
    )
    Logger.info(
        "[Config] Player movement debug: %s",
        "enabled" if player_movement_debug_enabled() else "disabled",
    )
