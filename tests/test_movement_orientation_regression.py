import struct
import sys
import time
from types import SimpleNamespace
import types


replay_module = types.ModuleType("server.modules.handlers.world.bootstrap.replay")
replay_module.build_database_gameobject_responses = lambda *args, **kwargs: []
replay_module.build_multi_u32_update_object_payload = lambda *args, **kwargs: b""
replay_module.build_single_u32_update_object_payload = lambda *args, **kwargs: b""
sys.modules.setdefault("server.modules.handlers.world.bootstrap.replay", replay_module)
creatures_module = types.ModuleType("server.modules.handlers.world.bootstrap.creatures")
creatures_module.build_database_creature_responses = lambda *args, **kwargs: []
sys.modules.setdefault("server.modules.handlers.world.bootstrap.creatures", creatures_module)

database_module = types.ModuleType("server.modules.database.DatabaseConnection")
database_module.DatabaseConnection = type(
    "DatabaseConnection",
    (),
    {
        "get_gameobjects_near": staticmethod(lambda *args, **kwargs: []),
    },
)
sys.modules.setdefault("server.modules.database.DatabaseConnection", database_module)

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
    assert round(orientation, 3) == round(2.64466, 3)


def test_parse_real_turning_heartbeat_right_uses_offset_24_orientation():
    session = _session()
    payload = bytes.fromhex("49364F4135837D4630FB7D4600000090014000002140000C353F014077CEF605")

    parsed = movement.parse_movement_info(
        session,
        "MSG_MOVE_HEARTBEAT",
        payload,
        decoded={},
    )

    assert parsed is not None
    _x, _y, _z, orientation = parsed
    assert round(orientation, 6) == round(2.019482851, 6)
    assert round(orientation, 6) != round(struct.unpack_from("<f", payload, 18)[0], 6)


def test_parse_real_turning_heartbeat_left_uses_offset_24_orientation():
    session = _session()
    payload = bytes.fromhex("EDC853416D897D4653057E4600000090014000000840000C29A54C4062C2F605")

    parsed = movement.parse_movement_info(
        session,
        "MSG_MOVE_HEARTBEAT",
        payload,
        decoded={},
    )

    assert parsed is not None
    _x, _y, _z, orientation = parsed
    assert round(orientation, 6) == round(3.197580576, 6)
    assert round(orientation, 6) != round(struct.unpack_from("<f", payload, 18)[0], 6)


def test_parse_real_airborne_heartbeat_uses_offset_43_orientation():
    session = _session()
    payload = bytes.fromhex(
        "A96B7741C1A27D4600FB7D46000000904540000800800C433FC7BE"
        "F6D16BBF00000000D893FEC0F4010000C3A4624015A52C05"
    )

    parsed = movement.parse_movement_info(
        session,
        "MSG_MOVE_HEARTBEAT",
        payload,
        decoded={},
    )

    assert parsed is not None
    _x, _y, _z, orientation = parsed
    assert round(orientation, 6) == round(3.541306257, 6)
    assert round(orientation, 6) != round(struct.unpack_from("<f", payload, 23)[0], 6)


def test_parse_real_air_spin_heartbeat_uses_offset_43_orientation():
    session = _session()
    payload = bytes.fromhex(
        "6568764171557D4600057E46000000904540000821800C88A77C3F"
        "4902253ECDCC0041D893FEC0A6020000A0E2063D77BE2C05"
    )

    parsed = movement.parse_movement_info(
        session,
        "MSG_MOVE_HEARTBEAT",
        payload,
        decoded={},
    )

    assert parsed is not None
    _x, _y, _z, orientation = parsed
    assert round(orientation, 6) == round(0.032930970, 6)
    assert round(orientation, 6) != round(struct.unpack_from("<f", payload, 23)[0], 6)


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


def test_parse_real_skyfire_40_byte_fall_land_uses_offset_36_orientation():
    session = _session()
    payload = bytes.fromhex(
        "DFEC7D4643F948414F817D4682880000041000000000040CB2030000"
        "D893FEC083B42C05C3A46240"
    )

    parsed = movement.parse_movement_info(
        session,
        "MSG_MOVE_FALL_LAND",
        payload,
        decoded={},
    )

    assert parsed is not None
    _x, _y, _z, orientation = parsed
    assert round(orientation, 6) == round(3.541306257, 6)
    assert round(orientation, 6) != round(struct.unpack_from("<f", payload, 32)[0], 6)


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
    assert round(x, 3) == round(16222.611328, 3)
    assert round(y, 3) == round(16255.974609, 3)
    assert round(z, 3) == round(12.992843, 3)
    assert round(orientation, 3) == round(2.64466, 3)


def test_parse_real_skyfire_32_byte_stop_uses_offset_24_orientation():
    session = _session()
    payload = bytes.fromhex(
        "F6AA7D46820D7E466B50644112000002009000000000A00C208D8E4043922C05"
    )

    parsed = movement.parse_movement_info(
        session,
        "MSG_MOVE_STOP",
        payload,
        decoded={},
    )

    assert parsed is not None
    _x, _y, _z, orientation = parsed
    assert round(orientation, 6) == round(4.454727173, 6)
    assert round(orientation, 6) != round(struct.unpack_from("<f", payload, 20)[0], 6)


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


def test_fall_land_clears_fall_data_in_movement_state():
    session = _session()
    state = movement._movement_state(session)
    state.has_fall_data = True
    state.fall_time = 123
    state.fall_vertical_speed = -7.9
    state.fall_horizontal_speed = 2.0
    state.fall_sin_angle = 0.47
    state.fall_cos_angle = -0.88

    movement._record_movement_packet_state(session, "MSG_MOVE_FALL_LAND", b"\x00" * 28)

    assert state.has_fall_data is False
    assert state.fall_time == 0
    assert state.fall_vertical_speed == 0.0
    assert state.fall_horizontal_speed == 0.0
    assert state.fall_sin_angle == 0.0
    assert state.fall_cos_angle == 0.0


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
    assert round(orientation, 3) == round(4.377170, 3)


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


def test_turning_heartbeat_updates_orientation():
    session = _session()
    movement._movement_state(session).flags = movement._MOVEMENTFLAG_RIGHT
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


def test_turning_heartbeat_real_payload_uses_correct_facing():
    session = _session()
    session.x = 0.0
    session.y = 0.0
    session.z = 0.0
    movement._movement_state(session).flags = (
        movement._MOVEMENTFLAG_FORWARD | movement._MOVEMENTFLAG_RIGHT
    )
    ctx = PacketContext(
        sock=None,
        direction="C→S",
        opcode=0,
        name="MSG_MOVE_HEARTBEAT",
        payload=bytes.fromhex("49364F4135837D4630FB7D4600000090014000002140000C353F014077CEF605"),
        decoded={},
    )

    movement.handle_movement_packet(session, ctx)

    assert round(session.orientation, 6) == round(2.019482851, 6)
    assert round(session.orientation, 6) != round(2.515625, 6)
    assert round(session.persist_orientation, 6) == round(2.019482851, 6)


def test_straight_heartbeat_real_payload_still_preserves_orientation():
    session = _session()
    session.x = 0.0
    session.y = 0.0
    session.z = 0.0
    movement._movement_state(session).flags = movement._MOVEMENTFLAG_FORWARD
    ctx = PacketContext(
        sock=None,
        direction="C→S",
        opcode=0,
        name="MSG_MOVE_HEARTBEAT",
        payload=bytes.fromhex("CEE04F417E7A7D46E0FF7D4600000090014000000140000C1C422940149DF605"),
        decoded={},
    )

    movement.handle_movement_packet(session, ctx)

    assert round(session.x, 3) == round(16222.623047, 3)
    assert session.orientation == 2.08364
    assert session.persist_orientation == 2.08364


def test_straight_heartbeat_recovers_from_zero_orientation_with_last_valid_facing():
    session = _session()
    session.orientation = 0.0
    state = movement._movement_state(session)
    state.orientation = 0.0
    state.last_valid_orientation = 4.900827
    state.flags = movement._MOVEMENTFLAG_FORWARD
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
            "facing": 4.900827,
        },
    )

    movement.handle_movement_packet(session, ctx)

    assert round(session.orientation, 6) == round(4.900827, 6)
    assert round(session.persist_orientation, 6) == round(4.900827, 6)


def test_airborne_heartbeat_accepts_valid_orientation_without_turn_flags():
    session = _session()
    session.x = 10.0
    session.y = 20.0
    session.z = 30.0
    session.orientation = 4.900827
    state = movement._movement_state(session)
    state.x = 10.0
    state.y = 20.0
    state.z = 30.0
    state.orientation = 4.900827
    state.flags = movement._MOVEMENTFLAG_FORWARD | movement._MOVEMENTFLAG_FALLING
    state.has_fall_data = True
    ctx = PacketContext(
        sock=None,
        direction="C→S",
        opcode=0,
        name="MSG_MOVE_HEARTBEAT",
        payload=b"",
        decoded={
            "x": 11.0,
            "y": 20.0,
            "z": 31.0,
            "facing": 0.839534,
        },
    )

    movement.handle_movement_packet(session, ctx)

    assert round(session.orientation, 6) == round(0.839534, 6)
    assert round(movement._movement_state(session).orientation, 6) == round(0.839534, 6)
    assert round(session.persist_orientation, 6) == round(0.839534, 6)


def test_airborne_real_heartbeat_accepts_blood_elf_air_spin_orientation():
    session = _session()
    session.x = 16227.683
    session.y = 16260.043
    session.z = 14.873
    session.orientation = 4.900827
    state = movement._movement_state(session)
    state.x = session.x
    state.y = session.y
    state.z = session.z
    state.orientation = session.orientation
    state.flags = movement._MOVEMENTFLAG_FORWARD | movement._MOVEMENTFLAG_FALLING
    state.has_fall_data = True
    ctx = PacketContext(
        sock=None,
        direction="C→S",
        opcode=0,
        name="MSG_MOVE_HEARTBEAT",
        payload=bytes.fromhex(
            "6568764171557D4600057E46000000904540000821800C88A77C3F"
            "4902253ECDCC0041D893FEC0A6020000A0E2063D77BE2C05"
        ),
        decoded={},
    )

    movement.handle_movement_packet(session, ctx)

    assert round(session.orientation, 6) == round(0.032930970, 6)
    assert round(movement._movement_state(session).orientation, 6) == round(0.032930970, 6)


def test_turning_heartbeat_with_invalid_orientation_keeps_previous_orientation():
    session = _session()
    movement._movement_state(session).flags = movement._MOVEMENTFLAG_RIGHT
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
            "facing": 100.0,
        },
    )

    movement.handle_movement_packet(session, ctx)

    assert session.x == 11.0
    assert session.orientation == 2.08364
    assert session.persist_orientation == 2.08364


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


def test_heartbeat_preserves_turn_flags_until_stop_turn():
    session = _session()
    movement._store_authoritative_movement(session, "MSG_MOVE_START_TURN_RIGHT", b"", None)
    assert movement._movement_state(session).flags & movement._MOVEMENTFLAG_RIGHT

    payload = bytes.fromhex("CEE04F417E7A7D46E0FF7D4600000090014000000140000C1C422940149DF605")
    parsed = movement.parse_movement_info(session, "MSG_MOVE_HEARTBEAT", payload, decoded={})
    assert parsed is not None
    movement._store_authoritative_movement(session, "MSG_MOVE_HEARTBEAT", payload, parsed)

    assert movement._movement_state(session).flags & movement._MOVEMENTFLAG_RIGHT

    movement._store_authoritative_movement(session, "MSG_MOVE_STOP_TURN", b"", None)

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
