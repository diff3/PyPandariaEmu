from datetime import datetime
from types import SimpleNamespace
import struct

from server.modules.handlers.world.calendar.service import CalendarService
from server.modules.handlers.world.dispatcher import HANDLERS, dispatch
from server.modules.handlers.world.opcodes import calendar as calendar_opcodes


def _ctx(opcode: str, payload: bytes = b""):
    return SimpleNamespace(name=opcode, payload=payload, decoded={})


def test_empty_calendar_matches_skyfire_zero_counts_and_times():
    timestamp = 1_720_000_000
    service = CalendarService(clock=lambda: timestamp)

    payload = service.serialize_empty_calendar()

    assert len(payload) == 24
    assert payload[:12] == bytes(12)
    assert struct.unpack_from("<I", payload, 12)[0] == service._packed_time(timestamp)
    assert struct.unpack_from("<II", payload, 16) == (1135753200, timestamp)


def test_open_calendar_and_pending_requests_always_receive_empty_responses():
    session = SimpleNamespace(disconnected=False)

    calendar_result = dispatch(session, "CMSG_CALENDAR_GET_CALENDAR", _ctx("CMSG_CALENDAR_GET_CALENDAR"))
    pending_result = dispatch(session, "CMSG_CALENDAR_GET_NUM_PENDING", _ctx("CMSG_CALENDAR_GET_NUM_PENDING"))

    assert calendar_result[1][0][0] == "SMSG_CALENDAR_SEND_CALENDAR"
    assert len(calendar_result[1][0][1]) == 24
    assert pending_result[1] == [("SMSG_CALENDAR_SEND_NUM_PENDING", bytes(4))]
    assert session.disconnected is False


def test_repeated_opening_is_stateless_and_safe():
    service = CalendarService(clock=lambda: 1_720_000_000)

    first = service.handle_request("CMSG_CALENDAR_GET_CALENDAR")
    second = service.handle_request("CMSG_CALENDAR_GET_CALENDAR")

    assert first == second


def test_every_defined_calendar_request_is_registered_and_answered():
    session = SimpleNamespace(disconnected=False)
    for opcode in calendar_opcodes.CALENDAR_REQUEST_OPCODES:
        assert opcode in HANDLERS
        status, responses = dispatch(session, opcode, _ctx(opcode, bytes(8)))
        assert status == 0
        assert responses and len(responses) == 1
        assert responses[0][0].startswith("SMSG_CALENDAR_")
    assert session.disconnected is False


def test_invalid_event_returns_valid_empty_parameter_command_result():
    service = CalendarService(clock=lambda: 1_720_000_000)

    responses = service.handle_request("CMSG_CALENDAR_GET_EVENT", struct.pack("<Q", 42))

    assert responses == [("SMSG_CALENDAR_COMMAND_RESULT", bytes.fromhex("00000006"))]
