#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest
import math

from server.modules.handlers.world.protocol.movement.spline import (
    SPLINE_FLAG_CATMULLROM,
    SPLINE_FLAG_FLYING,
    SPLINE_FLAG_UNCOMPRESSED_PATH,
    SPLINE_FLAG_WALKMODE,
    SplineFacingMode,
    SplineVector,
    MonsterMoveSpline,
    build_basic_spline_move,
    build_smsg_on_monster_move,
)


def test_build_basic_uncompressed_spline_matches_fixture():
    payload = build_basic_spline_move(
        mover_guid=0x1122334455667788,
        spline_id=0x12345678,
        start_position=SplineVector(1.0, 2.0, 3.0),
        path_points=(
            SplineVector(4.0, 5.0, 6.0),
        ),
        destination_position=SplineVector(7.0, 8.0, 9.0),
        spline_flags=(
            SPLINE_FLAG_FLYING
            | SPLINE_FLAG_CATMULLROM
            | SPLINE_FLAG_WALKMODE
            | SPLINE_FLAG_UNCOMPRESSED_PATH
        ),
        duration_ms=12345,
    )

    assert payload.hex() == (
        "000040400000803f7856341200000040000000000000000000000000"
        "c7000027bc00000800c0760000a040000080400000c0400000004100"
        "00e040000010413254000a6000238910674539300000"
    )


def test_build_facing_angle_spline_matches_fixture():
    payload = build_basic_spline_move(
        mover_guid=0x00000000000000AA,
        spline_id=7,
        start_position=SplineVector(10.0, 20.0, 30.0),
        destination_position=SplineVector(40.0, 50.0, 60.0),
        duration_ms=777,
        facing_angle=1.25,
    )

    assert payload.hex() == (
        "0000f04100002041070000000000a041000000000000000000000000"
        "e70000138800000000000000484200002042000070420000a03f000a"
        "6000ab09030000"
    )


def test_facing_angle_is_normalized_before_spline_serialization():
    kwargs = dict(
        mover_guid=0xAA,
        spline_id=7,
        start_position=SplineVector(10.0, 20.0, 30.0),
        destination_position=SplineVector(40.0, 50.0, 60.0),
        duration_ms=777,
    )
    assert build_basic_spline_move(facing_angle=math.tau + 1.25, **kwargs) == (
        build_basic_spline_move(facing_angle=1.25, **kwargs)
    )


def test_builder_rejects_compressed_paths_until_supported():
    spline = MonsterMoveSpline(
        mover_guid=1,
        spline_id=1,
        start_position=SplineVector(0.0, 0.0, 0.0),
        path_points=(SplineVector(1.0, 1.0, 1.0),),
        spline_flags=0,
        duration_ms=1,
    )

    with pytest.raises(NotImplementedError, match="compressed"):
        build_smsg_on_monster_move(spline)


def test_facing_point_requires_point():
    spline = MonsterMoveSpline(
        mover_guid=1,
        spline_id=1,
        start_position=SplineVector(0.0, 0.0, 0.0),
        path_points=(SplineVector(1.0, 1.0, 1.0),),
        spline_flags=SPLINE_FLAG_UNCOMPRESSED_PATH,
        duration_ms=1,
        facing_mode=SplineFacingMode.POINT,
    )

    with pytest.raises(ValueError, match="facing_point"):
        build_smsg_on_monster_move(spline)
