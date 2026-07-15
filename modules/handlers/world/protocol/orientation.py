"""Orientation conversion at the world protocol boundary."""

from __future__ import annotations

import math


def normalize_orientation(value: float) -> float:
    """Match SkyFire's Position::NormalizeOrientation for a wire yaw."""
    orientation = float(value)
    if not math.isfinite(orientation):
        raise ValueError(f"orientation must be finite, got {orientation!r}")
    if orientation < 0.0:
        return float(-math.fmod(abs(orientation), math.tau) + math.tau)
    return float(math.fmod(orientation, math.tau))
