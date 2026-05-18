#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Transport movement template accessors."""

from __future__ import annotations

from .cache import get_movement_cache
from .types import MovementTemplate


def transport_animation_template(entry: int) -> MovementTemplate | None:
    return get_movement_cache().transport_template(int(entry))


def taxi_path_transport_template(path_id: int) -> MovementTemplate | None:
    return get_movement_cache().taxi_template(int(path_id))
