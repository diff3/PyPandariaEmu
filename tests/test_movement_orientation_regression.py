import struct
import time
from types import SimpleNamespace

from server.modules.handlers.world.opcodes import movement
from server.modules.protocol.PacketContext import PacketContext


def _session():
    return SimpleNamespace(
        char_guid=2,
        world_guid=0x0003000100000002,
        realm_id=1,
        map_id=1,
        zone=3487,
        instance_id=0,
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=2.08364,
        persist_map_id=1,
        persist_zone=3487,
        persist_instance_id=0,
        persist_x=10.0,
        persist_y=20.0,
        persist_z=30.0,
        persist_orientation=2.08364,
        last_saved_map_id=1,
        last_saved_zone=3487,
        last_saved_instance_id=0,
        last_saved_x=10.0,
        last_saved_y=20.0,
        last_saved_z=30.0,
        last_saved_orientation=2.08364,
        last_position_save_at=time.time(),
        position_dirty=False,
        region=None,
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


def test_stationary_heartbeat_does_not_override_orientation():
    session = _session()
    ctx = PacketContext(
        sock=None,
        direction="C→S",
        opcode=0,
        name="MSG_MOVE_HEARTBEAT",
        payload=b"",
        decoded={
            "x": 10.0,
            "y": 20.0,
            "z": 30.0,
            "facing": -0.0,
        },
    )

    movement.handle_movement_packet(session, ctx)

    assert session.orientation == 2.08364
    assert session.persist_orientation == 2.08364


def test_moving_heartbeat_updates_orientation():
    session = _session()
    ctx = PacketContext(
        sock=None,
        direction="C→S",
        opcode=0,
        name="MSG_MOVE_HEARTBEAT",
        payload=b"",
        decoded={
            "x": 11.0,
            "y": 20.0,
            "z": 30.0,
            "facing": 1.5,
        },
    )

    movement.handle_movement_packet(session, ctx)

    assert session.x == 11.0
    assert session.orientation == 1.5
    assert session.persist_orientation == 1.5


def test_simulated_start_forward_then_stop_advances_position():
    session = _session()
    session.orientation = 0.0
    session.persist_orientation = 0.0
    session._sim_motion_updated_at = 100.0

    movement._mark_movement_state(session, "MSG_MOVE_START_FORWARD", now=100.0)
    movement._mark_movement_state(session, "MSG_MOVE_STOP", now=101.0)

    assert session.x > 16.5
    assert session.y == 20.0
    assert session.persist_x == session.x


def test_flush_simulated_movement_applies_pending_forward_motion():
    session = _session()
    session.orientation = 0.0
    session.persist_orientation = 0.0
    session._sim_motion_updated_at = 200.0

    movement._mark_movement_state(session, "MSG_MOVE_START_FORWARD", now=200.0)
    movement._flush_simulated_movement(session, now=201.0)

    assert session.x > 16.5
    assert session.persist_x == session.x
