#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Elevator movement template accessors."""

from __future__ import annotations

from .cache import get_movement_cache
from .types import MovementTemplate


def elevator_template(entry: int) -> MovementTemplate | None:
    return get_movement_cache().transport_template(int(entry))
