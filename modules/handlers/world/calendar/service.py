from __future__ import annotations

from datetime import datetime
import struct
import time
from typing import Callable

from DSL.modules.bitsHandler import BitWriter


CALENDAR_ERROR_EVENT_INVALID = 6
_SKYFIRE_CALENDAR_EPOCH = 1135753200


class CalendarService:
    """Own parsing and empty/default serialization for the calendar stub."""

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock

    @staticmethod
    def _packed_time(timestamp: int) -> int:
        value = datetime.fromtimestamp(int(timestamp))
        return (
            ((value.year - 2000) << 24)
            | ((value.month - 1) << 20)
            | ((value.day - 1) << 14)
            | (((value.weekday() + 1) % 7) << 11)
            | (value.hour << 6)
            | value.minute
        ) & 0xFFFFFFFF

    def serialize_empty_calendar(self) -> bytes:
        """Match HandleCalendarGetCalendar with no data or raid resets."""
        now = int(self._clock()) & 0xFFFFFFFF
        bits = BitWriter()
        bits.write_bits(0, 20)  # raid reset count
        bits.write_bits(0, 16)  # holiday count
        bits.write_bits(0, 20)  # lockout count
        bits.write_bits(0, 19)  # invite count
        bits.write_bits(0, 19)  # event count
        payload = bytearray(bits.getvalue())
        payload.extend(struct.pack("<I", self._packed_time(now)))
        payload.extend(struct.pack("<II", _SKYFIRE_CALENDAR_EPOCH, now))
        return bytes(payload)

    @staticmethod
    def serialize_num_pending() -> bytes:
        return struct.pack("<I", 0)

    @staticmethod
    def serialize_command_result(error: int = CALENDAR_ERROR_EVENT_INVALID) -> bytes:
        # Empty parameter: 8-bit half-length plus one odd-length bit, flushed.
        bits = BitWriter()
        bits.write_bits(0, 8)
        bits.write_bits(0, 1)
        return bits.getvalue() + struct.pack("<BB", 0, int(error) & 0xFF)

    @staticmethod
    def parse_event_id(payload: bytes) -> int:
        return struct.unpack_from("<Q", bytes(payload), 0)[0] if len(payload) >= 8 else 0

    def handle_request(self, opcode: str, payload: bytes = b"") -> list[tuple[str, bytes]]:
        if opcode == "CMSG_CALENDAR_GET_CALENDAR":
            return [("SMSG_CALENDAR_SEND_CALENDAR", self.serialize_empty_calendar())]
        if opcode == "CMSG_CALENDAR_GET_NUM_PENDING":
            # SkyFire answers this bootstrap request with the pending count
            # only. The full calendar is sent exclusively in response to
            # CMSG_CALENDAR_GET_CALENDAR.
            return [("SMSG_CALENDAR_SEND_NUM_PENDING", self.serialize_num_pending())]
        if opcode == "CMSG_CALENDAR_GET_EVENT":
            self.parse_event_id(payload)
        return [("SMSG_CALENDAR_COMMAND_RESULT", self.serialize_command_result())]


_SERVICE: CalendarService | None = None


def get_calendar_service() -> CalendarService:
    global _SERVICE
    if _SERVICE is None:
        _SERVICE = CalendarService()
    return _SERVICE
