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


def test_parse_real_skyfire_heartbeat_uses_zxy_prefix():
    session = _session()
    payload = bytes.fromhex("CEE04F417E7A7D46E0FF7D4600000090014000000140000C1C422940149DF605")

    parsed = movement.parse_movement_info(
        session,
        "MSG_MOVE_HEARTBEAT",
        payload,
        decoded={},
    )

    assert parsed is not None
    x, y, z, orientation = parsed
    assert round(x, 3) == round(16222.623047, 3)
    assert round(y, 3) == round(16255.96875, 3)
    assert round(z, 3) == round(12.992384, 3)
    assert orientation == session.orientation


def test_parse_real_skyfire_fall_land_uses_yzx_prefix():
    session = _session()
    payload = bytes.fromhex("F1107E46E355564137907D46828800000C1000090F00000000000000A27BF6057FFD8240")

    parsed = movement.parse_movement_info(
        session,
        "MSG_MOVE_FALL_LAND",
        payload,
        decoded={},
    )

    assert parsed is not None
    x, y, z, orientation = parsed
    assert round(x, 3) == round(16228.053711, 3)
    assert round(y, 3) == round(16260.235352, 3)
    assert round(z, 3) == round(13.395968, 3)
    assert orientation == session.orientation


def test_parse_real_skyfire_start_forward_uses_zxy_prefix_and_orientation():
    session = _session()
    payload = bytes.fromhex("EFD74F41CD867D4633F97D4628000000421000000000080C209BF6051C422940")

    parsed = movement.parse_movement_info(
        session,
        "MSG_MOVE_START_FORWARD",
        payload,
        decoded={},
    )

    assert parsed is not None
    x, y, z, orientation = parsed
    assert round(x, 3) == round(16225.700195, 3)
    assert round(y, 3) == round(16254.299805, 3)
    assert round(z, 3) == round(12.990218, 3)
    assert round(orientation, 3) == round(2.64466, 3)


def test_parse_real_skyfire_stop_uses_xyz_prefix_and_orientation():
    session = _session()
    payload = bytes.fromhex("727A7D46E6FF7D46AFE24F41120000020890000C1C422940169DF605")

    parsed = movement.parse_movement_info(
        session,
        "MSG_MOVE_STOP",
        payload,
        decoded={},
    )

    assert parsed is not None
    x, y, z, orientation = parsed
    assert round(x, 3) == round(16222.613281, 3)
    assert round(y, 3) == round(16255.974609, 3)
    assert round(z, 3) == round(12.992843, 3)
    assert round(orientation, 3) == round(2.64466, 3)


def test_parse_real_skyfire_jump_uses_yxz_prefix_and_orientation():
    session = _session()
    payload = bytes.fromhex("59F77D46368A7D465978504108000000494000080040040CD893FEC02516F43E5B0961BF00000000000000001C422940C6A5F605")

    parsed = movement.parse_movement_info(
        session,
        "MSG_MOVE_JUMP",
        payload,
        decoded={},
    )

    assert parsed is not None
    x, y, z, orientation = parsed
    assert round(x, 3) == round(16226.552734, 3)
    assert round(y, 3) == round(16253.836914, 3)
    assert round(z, 3) == round(13.029381, 3)
    assert round(orientation, 3) == round(2.64466, 3)


def test_jump_records_fall_data_in_movement_state():
    session = _session()
    payload = bytes.fromhex("59F77D46368A7D465978504108000000494000080040040CD893FEC02516F43E5B0961BF00000000000000001C422940C6A5F605")

    movement._record_movement_packet_state(session, "MSG_MOVE_JUMP", payload)
    state = movement._movement_state(session)

    assert state.has_fall_data is True
    assert round(state.fall_vertical_speed, 3) == round(-7.955547, 3)
    assert round(state.fall_sin_angle, 3) == round(0.476731, 3)
    assert round(state.fall_cos_angle, 3) == round(-0.879049, 3)


def test_parse_real_skyfire_start_turn_right_uses_xzy_prefix_and_orientation():
    session = _session()
    payload = bytes.fromhex("368A7D46ED85504159F77D4613000002000000002040000C1C422940F9AAF605")

    parsed = movement.parse_movement_info(
        session,
        "MSG_MOVE_START_TURN_RIGHT",
        payload,
        decoded={},
    )

    assert parsed is not None
    x, y, z, orientation = parsed
    assert round(x, 3) == round(16226.552734, 3)
    assert round(y, 3) == round(16253.836914, 3)
    assert round(z, 3) == round(13.032697, 3)
    assert round(orientation, 3) == round(2.441416, 3)


def test_parse_real_skyfire_start_turn_left_uses_zxy_prefix_and_orientation():
    session = _session()
    payload = bytes.fromhex("ED855041368A7D4659F77D4601080000030000001040000CF8ED104072B4F605")

    parsed = movement.parse_movement_info(
        session,
        "MSG_MOVE_START_TURN_LEFT",
        payload,
        decoded={},
    )

    assert parsed is not None
    x, y, z, orientation = parsed
    assert round(x, 3) == round(16226.552734, 3)
    assert round(y, 3) == round(16253.836914, 3)
    assert round(z, 3) == round(13.032697, 3)
    assert round(orientation, 3) == round(2.264524, 3)


def test_parse_real_skyfire_stop_turn_uses_xzy_prefix_and_orientation():
    session = _session()
    payload = bytes.fromhex("368A7D46ED85504159F77D4600000022A210000C91D8873FF1ACF605")

    parsed = movement.parse_movement_info(
        session,
        "MSG_MOVE_STOP_TURN",
        payload,
        decoded={},
    )

    assert parsed is not None
    x, y, z, orientation = parsed
    assert round(x, 3) == round(16226.552734, 3)
    assert round(y, 3) == round(16253.836914, 3)
    assert round(z, 3) == round(13.032697, 3)
    assert round(orientation, 3) == round(1.061297, 3)


def test_parse_real_skyfire_stop_turn_32_byte_variant_uses_offset_24_orientation():
    session = _session()
    payload = bytes.fromhex("EB8E7D46DC1F5041D4F17D46000000228210000000000809C7118C40A613E006")

    parsed = movement.parse_movement_info(
        session,
        "MSG_MOVE_STOP_TURN",
        payload,
        decoded={},
    )

    assert parsed is not None
    x, y, z, orientation = parsed
    assert round(x, 3) == round(16227.729492, 3)
    assert round(y, 3) == round(16252.457031, 3)
    assert round(z, 3) == round(13.007778, 3)
    assert round(orientation, 3) == round(4.378147, 3)


def test_exact_skyfire_parse_wins_over_bad_decoded_turn_data():
    session = _session()
    payload = bytes.fromhex("368A7D46ED85504159F77D4600000022A210000C91D8873FF1ACF605")

    parsed = movement.parse_movement_info(
        session,
        "MSG_MOVE_STOP_TURN",
        payload,
        decoded={
            "x": 16226.552734375,
            "y": 16253.8369140625,
            "z": 13.032696723937988,
            "facing": 0.0,
        },
    )

    assert parsed is not None
    x, y, z, orientation = parsed
    assert round(x, 3) == round(16226.552734, 3)
    assert round(y, 3) == round(16253.836914, 3)
    assert round(z, 3) == round(13.032697, 3)
    assert round(orientation, 3) == round(1.061297, 3)


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


def test_moving_decoded_heartbeat_updates_position_but_keeps_orientation():
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
    assert session.y == 20.0
    assert session.z == 30.0
    assert session.orientation == 2.08364


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


def test_state_only_packets_update_movement_state_flags():
    session = _session()
    movement._store_authoritative_movement(session, "MSG_MOVE_START_FORWARD", b"", None)
    assert movement._movement_state(session).flags & movement._MOVEMENTFLAG_FORWARD

    movement._store_authoritative_movement(session, "MSG_MOVE_START_TURN_RIGHT", b"", None)
    assert movement._movement_state(session).flags & movement._MOVEMENTFLAG_RIGHT

    movement._store_authoritative_movement(session, "MSG_MOVE_STOP_TURN", b"", None)
    assert (movement._movement_state(session).flags & movement._MOVEMENTFLAG_RIGHT) == 0

    movement._store_authoritative_movement(session, "MSG_MOVE_STOP", b"", None)
    assert (movement._movement_state(session).flags & movement._MOVEMENTFLAG_FORWARD) == 0


def test_heartbeat_clears_turn_flags_in_authoritative_state():
    session = _session()
    movement._store_authoritative_movement(session, "MSG_MOVE_START_TURN_RIGHT", b"", None)
    assert movement._movement_state(session).flags & movement._MOVEMENTFLAG_RIGHT

    payload = bytes.fromhex("CEE04F417E7A7D46E0FF7D4600000090014000000140000C1C422940149DF605")
    parsed = movement.parse_movement_info(session, "MSG_MOVE_HEARTBEAT", payload, decoded={})
    assert parsed is not None
    movement._store_authoritative_movement(session, "MSG_MOVE_HEARTBEAT", payload, parsed)

    assert (movement._movement_state(session).flags & movement._MOVEMENTFLAG_RIGHT) == 0


def test_stale_turn_packet_does_not_override_newer_timestamp_state():
    session = _session()
    state = movement._movement_state(session)
    state.timestamp_ms = 2000
    state.x = 100.0
    state.y = 200.0
    state.z = 300.0
    state.orientation = 1.5

    stale_payload = b"\x00" * 24 + (1500).to_bytes(4, "little", signed=False)
    stored = movement._store_authoritative_movement(
        session,
        "MSG_MOVE_STOP_TURN",
        stale_payload,
        (1.0, 2.0, 3.0, 0.5),
    )

    assert stored is False
    assert movement._movement_state(session).timestamp_ms == 2000
    assert movement._movement_state(session).x == 100.0
    assert movement._movement_state(session).orientation == 1.5
