import struct
from types import SimpleNamespace

from server.modules.handlers.world.opcodes import movement


def _session():
    return SimpleNamespace(
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=2.08364,
    )


def test_parse_movement_info_does_not_bruteforce_stop_turn_payload():
    session = _session()
    payload = struct.pack("<ffff", 10.0, 20.0, 30.0, 0.0)

    parsed = movement.parse_movement_info(
        session,
        "MSG_MOVE_STOP_TURN",
        payload,
        decoded={},
    )

    assert parsed is None


def test_parse_movement_info_still_bruteforces_heartbeat_payload():
    session = _session()
    payload = struct.pack("<ffff", 10.5, 20.25, 29.75, 1.5)

    parsed = movement.parse_movement_info(
        session,
        "MSG_MOVE_HEARTBEAT",
        payload,
        decoded={},
    )

    assert parsed is not None
    x, y, z, orientation = parsed
    assert x == 10.5
    assert y == 20.25
    assert z == 29.75
    assert orientation == 1.5
