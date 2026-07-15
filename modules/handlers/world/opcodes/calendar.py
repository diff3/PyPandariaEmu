"""Opcode routing for the isolated minimal calendar service."""

from __future__ import annotations

from server.modules.handlers.world.calendar import get_calendar_service
from server.modules.handlers.world.dispatcher import register


CALENDAR_REQUEST_OPCODES = (
    "CMSG_CALENDAR_GET_CALENDAR",
    "CMSG_CALENDAR_GET_NUM_PENDING",
    "CMSG_CALENDAR_GET_EVENT",
    "CMSG_CALENDAR_ADD_EVENT",
    "CMSG_CALENDAR_COMPLAIN",
    "CMSG_CALENDAR_COPY_EVENT",
    "CMSG_CALENDAR_EVENT_INVITE",
    "CMSG_CALENDAR_EVENT_MODERATOR_STATUS",
    "CMSG_CALENDAR_EVENT_REMOVE_INVITE",
    "CMSG_CALENDAR_EVENT_RSVP",
    "CMSG_CALENDAR_EVENT_SIGNUP",
    "CMSG_CALENDAR_EVENT_STATUS",
    "CMSG_CALENDAR_REMOVE_EVENT",
    "CMSG_CALENDAR_UPDATE_EVENT",
)


def handle_calendar_request(session, ctx):
    responses = get_calendar_service().handle_request(
        str(ctx.name),
        bytes(ctx.payload or b""),
    )
    return 0, responses


for _opcode in CALENDAR_REQUEST_OPCODES:
    register(_opcode)(handle_calendar_request)
