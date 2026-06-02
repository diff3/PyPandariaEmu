#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""MoP 5.4.8 spline movement packet builders."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import struct

from DSL.modules.bitsHandler import BitWriter


MONSTER_MOVE_NORMAL = 0
MONSTER_MOVE_FACING_POINT = 2
MONSTER_MOVE_FACING_TARGET = 3
MONSTER_MOVE_FACING_ANGLE = 4

SPLINE_FLAG_FALLING_SLOW = 0x00000010
SPLINE_FLAG_FALLING = 0x00000040
SPLINE_FLAG_FLYING = 0x00000200
SPLINE_FLAG_ORIENTATION_FIXED = 0x00000400
SPLINE_FLAG_CATMULLROM = 0x00000800
SPLINE_FLAG_CYCLIC = 0x00001000
SPLINE_FLAG_TRANSPORT_ENTER = 0x00008000
SPLINE_FLAG_TRANSPORT_EXIT = 0x00010000
SPLINE_FLAG_ORIENTATION_INVERSED = 0x00080000
SPLINE_FLAG_SMOOTH_GROUND_PATH = 0x00100000
SPLINE_FLAG_WALKMODE = 0x00200000
SPLINE_FLAG_UNCOMPRESSED_PATH = 0x00400000
SPLINE_FLAG_PARABOLIC = 0x02000000
SPLINE_FLAG_FINAL_POINT = 0x04000000
SPLINE_FLAG_FINAL_TARGET = 0x08000000
SPLINE_FLAG_FINAL_ANGLE = 0x10000000

SPLINE_FLAG_MASK_FINAL_FACING = (
    SPLINE_FLAG_FINAL_POINT
    | SPLINE_FLAG_FINAL_TARGET
    | SPLINE_FLAG_FINAL_ANGLE
)
SPLINE_FLAG_MASK_ANIMATIONS = 0x00000007
SPLINE_FLAG_DONE = 0x00000020
SPLINE_FLAG_MASK_NO_MONSTER_MOVE = (
    SPLINE_FLAG_MASK_FINAL_FACING
    | SPLINE_FLAG_MASK_ANIMATIONS
    | SPLINE_FLAG_DONE
)

TAXI_SPLINE_FLAGS = (
    SPLINE_FLAG_FLYING
    | SPLINE_FLAG_CATMULLROM
    | SPLINE_FLAG_WALKMODE
    | SPLINE_FLAG_UNCOMPRESSED_PATH
)


class SplineFacingMode(IntEnum):
    NORMAL = MONSTER_MOVE_NORMAL
    POINT = MONSTER_MOVE_FACING_POINT
    TARGET = MONSTER_MOVE_FACING_TARGET
    ANGLE = MONSTER_MOVE_FACING_ANGLE


@dataclass(frozen=True)
class SplineVector:
    x: float
    y: float
    z: float


@dataclass(frozen=True)
class MonsterMoveSpline:
    mover_guid: int
    spline_id: int
    start_position: SplineVector
    path_points: tuple[SplineVector, ...]
    spline_flags: int
    duration_ms: int
    facing_mode: SplineFacingMode = SplineFacingMode.NORMAL
    facing_angle: float | None = None
    facing_point: SplineVector | None = None
    transport_guid: int = 0
    transport_offset: SplineVector = SplineVector(0.0, 0.0, 0.0)
    transport_seat: int | None = None


def build_smsg_on_monster_move(spline: MonsterMoveSpline) -> bytes:
    """Build a basic SMSG_ON_MONSTER_MOVE/SMSG_MONSTER_MOVE payload."""

    _validate_spline(spline)

    raw_guid = _raw_guid(int(spline.mover_guid))
    raw_transport = _raw_guid(int(spline.transport_guid))
    facing_mode = SplineFacingMode(spline.facing_mode)
    send_spline_flags = _monster_move_spline_flags(int(spline.spline_flags))
    duration = max(0, int(spline.duration_ms))
    path_points = tuple(spline.path_points)
    has_transport_seat = spline.transport_seat is not None

    payload = bytearray()
    payload.extend(struct.pack("<f", float(spline.start_position.z)))
    payload.extend(struct.pack("<f", float(spline.start_position.x)))
    payload.extend(struct.pack("<I", int(spline.spline_id) & 0xFFFFFFFF))
    payload.extend(struct.pack("<f", float(spline.start_position.y)))
    payload.extend(struct.pack("<f", float(spline.transport_offset.y)))
    payload.extend(struct.pack("<f", float(spline.transport_offset.z)))
    payload.extend(struct.pack("<f", float(spline.transport_offset.x)))

    bits = BitWriter()
    bits.write_bits(0 if _has_flag(spline.spline_flags, SPLINE_FLAG_PARABOLIC) else 1, 1)
    bits.write_bits(1 if raw_guid[0] else 0, 1)
    bits.write_bits(int(facing_mode), 3)

    if facing_mode == SplineFacingMode.TARGET:
        raise NotImplementedError("SMSG_ON_MONSTER_MOVE facing target is not implemented")

    bits.write_bits(1, 1)
    bits.write_bits(1, 1)
    bits.write_bits(0 if has_transport_seat else 1, 1)
    bits.write_bits(len(path_points), 20)
    bits.write_bits(0 if send_spline_flags else 1, 1)
    bits.write_bits(1 if raw_guid[3] else 0, 1)
    bits.write_bits(1, 1)
    bits.write_bits(1, 1)
    bits.write_bits(1, 1)
    bits.write_bits(0 if duration else 1, 1)
    bits.write_bits(1 if raw_guid[7] else 0, 1)
    bits.write_bits(1 if raw_guid[4] else 0, 1)
    bits.write_bits(1, 1)
    bits.write_bits(1 if raw_guid[5] else 0, 1)
    bits.write_bits(0, 22)  # compressed waypoint count
    bits.write_bits(1 if raw_guid[6] else 0, 1)
    bits.write_bits(0, 1)  # reference-core fake bit
    _write_guid_mask_bits(bits, raw_transport, (7, 1, 3, 0, 6, 4, 5, 2))
    bits.write_bits(0, 1)  # no unknown block
    bits.write_bits(0, 1)
    bits.write_bits(1 if raw_guid[2] else 0, 1)
    bits.write_bits(1 if raw_guid[1] else 0, 1)
    payload.extend(bits.getvalue())

    _append_guid_xor_bytes(payload, raw_guid, (1,))
    _append_guid_xor_bytes(payload, raw_transport, (6, 4, 1, 7, 0, 3, 5, 2))
    for point in path_points:
        payload.extend(struct.pack("<fff", float(point.y), float(point.x), float(point.z)))

    _append_guid_xor_bytes(payload, raw_guid, (5,))

    if facing_mode == SplineFacingMode.ANGLE:
        payload.extend(struct.pack("<f", float(spline.facing_angle)))

    _append_guid_xor_bytes(payload, raw_guid, (3,))

    if send_spline_flags:
        payload.extend(struct.pack("<I", send_spline_flags & 0xFFFFFFFF))

    _append_guid_xor_bytes(payload, raw_guid, (6,))

    if facing_mode == SplineFacingMode.POINT:
        point = spline.facing_point
        assert point is not None
        payload.extend(struct.pack("<fff", float(point.x), float(point.y), float(point.z)))

    _append_guid_xor_bytes(payload, raw_guid, (0,))

    if has_transport_seat:
        payload.append(int(spline.transport_seat or 0) & 0xFF)

    _append_guid_xor_bytes(payload, raw_guid, (7, 2, 4))

    if duration:
        payload.extend(struct.pack("<I", duration & 0xFFFFFFFF))

    return bytes(payload)


def build_basic_spline_move(
    *,
    mover_guid: int,
    spline_id: int,
    start_position: SplineVector,
    destination_position: SplineVector,
    path_points: tuple[SplineVector, ...] = (),
    spline_flags: int = TAXI_SPLINE_FLAGS,
    duration_ms: int,
    facing_angle: float | None = None,
) -> bytes:
    """Build the common uncompressed spline form used by taxi-like paths."""

    facing_mode = (
        SplineFacingMode.ANGLE
        if facing_angle is not None
        else SplineFacingMode.NORMAL
    )
    serialized_points = tuple(path_points) + (destination_position,)
    return build_smsg_on_monster_move(
        MonsterMoveSpline(
            mover_guid=int(mover_guid),
            spline_id=int(spline_id),
            start_position=start_position,
            path_points=serialized_points,
            spline_flags=int(spline_flags) | SPLINE_FLAG_UNCOMPRESSED_PATH,
            duration_ms=int(duration_ms),
            facing_mode=facing_mode,
            facing_angle=facing_angle,
        )
    )


def _validate_spline(spline: MonsterMoveSpline) -> None:
    if int(spline.mover_guid) < 0:
        raise ValueError("mover_guid must be non-negative")
    if int(spline.spline_id) < 0:
        raise ValueError("spline_id must be non-negative")
    if int(spline.duration_ms) < 0:
        raise ValueError("duration_ms must be non-negative")
    if not spline.path_points:
        raise ValueError("path_points must contain at least one serialized point")
    if not _has_flag(spline.spline_flags, SPLINE_FLAG_UNCOMPRESSED_PATH):
        raise NotImplementedError("compressed SMSG_ON_MONSTER_MOVE paths are not implemented")
    if _has_flag(spline.spline_flags, SPLINE_FLAG_CYCLIC):
        raise NotImplementedError("cyclic SMSG_ON_MONSTER_MOVE paths are not implemented")

    facing_mode = SplineFacingMode(spline.facing_mode)
    if facing_mode == SplineFacingMode.ANGLE and spline.facing_angle is None:
        raise ValueError("facing_angle is required for facing-angle spline movement")
    if facing_mode == SplineFacingMode.POINT and spline.facing_point is None:
        raise ValueError("facing_point is required for facing-point spline movement")
    if facing_mode == SplineFacingMode.TARGET:
        raise NotImplementedError("facing-target SMSG_ON_MONSTER_MOVE is not implemented")
    if _has_flag(spline.spline_flags, SPLINE_FLAG_PARABOLIC):
        raise NotImplementedError("parabolic SMSG_ON_MONSTER_MOVE paths are not implemented")


def _monster_move_spline_flags(spline_flags: int) -> int:
    flags = int(spline_flags) & 0xFFFFFFFF
    if _has_flag(flags, SPLINE_FLAG_TRANSPORT_ENTER):
        return SPLINE_FLAG_TRANSPORT_ENTER
    return flags & ~SPLINE_FLAG_MASK_NO_MONSTER_MOVE


def _has_flag(value: int, flag: int) -> bool:
    return bool(int(value) & int(flag))


def _raw_guid(guid: int) -> bytes:
    return int(guid & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little", signed=False)


def _write_guid_mask_bits(bits: BitWriter, raw_guid: bytes, order: tuple[int, ...]) -> None:
    for index in order:
        bits.write_bits(1 if raw_guid[index] else 0, 1)


def _append_guid_xor_bytes(
    payload: bytearray,
    raw_guid: bytes,
    order: tuple[int, ...],
) -> None:
    for index in order:
        value = raw_guid[index]
        if value:
            payload.append((value ^ 1) & 0xFF)
