#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generic movement debug helpers."""

from __future__ import annotations

from shared.Logger import Logger

from .manager import get_movement_manager


def log_movement_stats() -> None:
    stats = get_movement_manager().stats()
    Logger.info(
        "[MovementDebug] instances=%s transport_templates=%s taxi_templates=%s",
        stats["instances"],
        stats["transport_templates"],
        stats["taxi_templates"],
    )
