#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Taxi movement template accessors."""

from __future__ import annotations

from .cache import get_movement_cache
from .types import MovementTemplate


def taxi_template(path_id: int) -> MovementTemplate | None:
    return get_movement_cache().taxi_template(int(path_id))
