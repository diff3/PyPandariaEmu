#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared interpolation helpers for DBC movement templates."""

from __future__ import annotations

import bisect
import math

from .types import ArcLengthSample, MovementNode


INTERPOLATION_LINEAR = "LINEAR"
INTERPOLATION_SPLINE = "SPLINE"


def distance(a: MovementNode | ArcLengthSample, b: MovementNode | ArcLengthSample) -> float:
    dx = float(b.x) - float(a.x)
    dy = float(b.y) - float(a.y)
    dz = float(b.z) - float(a.z)
    return math.sqrt((dx * dx) + (dy * dy) + (dz * dz))


def heading_from_delta(dx: float, dy: float, fallback: float = 0.0) -> float:
    if abs(dx) <= 0.0001 and abs(dy) <= 0.0001:
        return float(fallback)
    return math.atan2(float(dy), float(dx)) % (math.pi * 2.0)


def linear_interpolate(
    start: MovementNode,
    end: MovementNode,
    t: float,
) -> tuple[float, float, float]:
    value = max(0.0, min(1.0, float(t)))

    return (
        float(start.x) + ((float(end.x) - float(start.x)) * value),
        float(start.y) + ((float(end.y) - float(start.y)) * value),
        float(start.z) + ((float(end.z) - float(start.z)) * value),
    )


def catmull_rom(
    p0: MovementNode,
    p1: MovementNode,
    p2: MovementNode,
    p3: MovementNode,
    t: float,
) -> tuple[float, float, float]:
    value = max(0.0, min(1.0, float(t)))
    t2 = value * value
    t3 = t2 * value

    #
    # Smooth spline for horizontal movement.
    #
    x = _catmull_axis(
        float(p0.x),
        float(p1.x),
        float(p2.x),
        float(p3.x),
        value,
        t2,
        t3,
    )

    y = _catmull_axis(
        float(p0.y),
        float(p1.y),
        float(p2.y),
        float(p3.y),
        value,
        t2,
        t3,
    )

    #
    # Linear interpolation for height.
    #
    # Prevents Catmull-Rom overshoot and vertical wobble
    # on taxi paths with uneven Z samples.
    #
    z = float(p1.z) + (
        (float(p2.z) - float(p1.z)) * value
    )

    return (x, y, z)


def build_arc_lengths(
    nodes: tuple[MovementNode, ...],
    *,
    samples_per_segment: int = 32,
    interpolation_mode: str = INTERPOLATION_SPLINE,
) -> tuple[ArcLengthSample, ...]:
    if len(nodes) < 2:
        return ()

    mode = _resolve_interpolation_mode(nodes, interpolation_mode)

    samples: list[ArcLengthSample] = [
        ArcLengthSample(
            0,
            0.0,
            0.0,
            int(nodes[0].map_id),
            float(nodes[0].x),
            float(nodes[0].y),
            float(nodes[0].z),
        )
    ]

    total = 0.0
    previous = samples[0]
    segment_samples = max(2, int(samples_per_segment))

    for index in range(len(nodes) - 1):
        current = nodes[index]
        target = nodes[index + 1]

        if int(current.map_id) != int(target.map_id):
            sample = ArcLengthSample(
                index + 1,
                1.0,
                total,
                int(target.map_id),
                float(target.x),
                float(target.y),
                float(target.z),
            )
            samples.append(sample)
            previous = sample
            continue

        p0 = nodes[max(0, index - 1)]
        p3 = nodes[min(len(nodes) - 1, index + 2)]

        for step in range(1, segment_samples + 1):
            t = float(step) / float(segment_samples)

            x, y, z = interpolate_position(
                mode,
                p0,
                current,
                target,
                p3,
                t,
            )

            sample_node = ArcLengthSample(
                index,
                t,
                0.0,
                int(current.map_id),
                x,
                y,
                z,
            )

            total += _sample_distance(previous, sample_node)

            sample = ArcLengthSample(
                index,
                t,
                total,
                int(current.map_id),
                x,
                y,
                z,
            )

            samples.append(sample)
            previous = sample

    return tuple(samples)


def interpolate_position(
    interpolation_mode: str,
    p0: MovementNode,
    p1: MovementNode,
    p2: MovementNode,
    p3: MovementNode,
    t: float,
) -> tuple[float, float, float]:
    mode = str(interpolation_mode).upper()

    if mode == INTERPOLATION_LINEAR:
        return linear_interpolate(p1, p2, t)

    return catmull_rom(p0, p1, p2, p3, t)


def sample_by_distance(
    samples: tuple[ArcLengthSample, ...],
    target_distance: float,
) -> ArcLengthSample:
    if not samples:
        raise ValueError("arc length table is empty")

    if len(samples) == 1:
        return samples[0]

    distances = [float(sample.distance) for sample in samples]

    index = bisect.bisect_left(distances, float(target_distance))

    if index <= 0:
        return samples[0]

    if index >= len(samples):
        return samples[-1]

    previous = samples[index - 1]
    current = samples[index]

    span = max(
        0.0001,
        float(current.distance) - float(previous.distance),
    )

    ratio = max(
        0.0,
        min(
            1.0,
            (float(target_distance) - float(previous.distance)) / span,
        ),
    )

    return ArcLengthSample(
        current.node_index,
        current.t,
        float(target_distance),
        int(previous.map_id if ratio < 0.5 else current.map_id),
        float(previous.x) + ((float(current.x) - float(previous.x)) * ratio),
        float(previous.y) + ((float(current.y) - float(previous.y)) * ratio),
        float(previous.z) + ((float(current.z) - float(previous.z)) * ratio),
    )


def _resolve_interpolation_mode(
    nodes: tuple[MovementNode, ...],
    requested_mode: str,
) -> str:
    mode = str(requested_mode).upper()

    if mode == INTERPOLATION_LINEAR:
        return INTERPOLATION_LINEAR

    if len(nodes) <= 3:
        return INTERPOLATION_LINEAR

    horizontal_distance = _horizontal_path_distance(nodes)

    if horizontal_distance <= 5.0:
        return INTERPOLATION_LINEAR

    return INTERPOLATION_SPLINE


def _horizontal_path_distance(nodes: tuple[MovementNode, ...]) -> float:
    total = 0.0

    for index in range(len(nodes) - 1):
        current = nodes[index]
        target = nodes[index + 1]

        dx = float(target.x) - float(current.x)
        dy = float(target.y) - float(current.y)

        total += math.sqrt((dx * dx) + (dy * dy))

    return total


def _catmull_axis(
    p0: float,
    p1: float,
    p2: float,
    p3: float,
    t: float,
    t2: float,
    t3: float,
) -> float:
    return 0.5 * (
        (2.0 * p1)
        + ((-p0 + p2) * t)
        + ((2.0 * p0 - 5.0 * p1 + 4.0 * p2 - p3) * t2)
        + ((-p0 + 3.0 * p1 - 3.0 * p2 + p3) * t3)
    )


def _sample_distance(a: ArcLengthSample, b: ArcLengthSample) -> float:
    dx = float(b.x) - float(a.x)
    dy = float(b.y) - float(a.y)
    dz = float(b.z) - float(a.z)

    return math.sqrt((dx * dx) + (dy * dy) + (dz * dz))