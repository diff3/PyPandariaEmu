import math

import pytest

from server.modules.handlers.world.protocol.orientation import normalize_orientation


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (0.25, 0.25),
        (math.tau + 0.25, 0.25),
        (-0.25, math.tau - 0.25),
        (3.0 * math.tau + 1.0, 1.0),
    ],
)
def test_normalize_orientation_matches_skyfire_period_semantics(raw, expected):
    assert normalize_orientation(raw) == pytest.approx(expected)

