import socket
import struct
import time

from server.authserver import (
    AUTH_RATE_LIMIT,
    AUTH_RATE_MAX,
    ConnectionContext,
    INITIAL_STATE,
    StepResult,
    apply_auth_rate_result,
    auth_rate_limit_exceeded,
    next_state,
    previous_state,
    step_controller,
)
from server.modules.handlers.AuthHandlers import build_REALM_LIST_S
from server.modules.protocol.PacketContext import PacketContext


def _packet(name: str, decoded=None) -> PacketContext:
    left, right = socket.socketpair()
    left.close()
    return PacketContext(
        sock=right,
        direction="C",
        opcode=0,
        name=name,
        payload=b"\x00",
        decoded=dict(decoded or {}),
    )


def test_state_helpers_follow_expected_auth_flow():
    assert next_state("AUTH_LOGON_CHALLENGE") == "AUTH_LOGON_PROOF"
    assert next_state("AUTH_LOGON_PROOF") == "REALM_LIST"
    assert next_state("REALM_LIST") == "REALM_LIST"
    assert previous_state("REALM_LIST") == "AUTH_LOGON_PROOF"
    assert previous_state("AUTH_LOGON_PROOF") == "AUTH_LOGON_CHALLENGE"
    assert previous_state("AUTH_LOGON_CHALLENGE") == INITIAL_STATE


def test_successful_logins_never_accumulate_rate_limit_entries():
    ip = "192.0.2.10"
    AUTH_RATE_LIMIT.pop(ip, None)

    for attempt in range(AUTH_RATE_MAX * 3):
        apply_auth_rate_result(
            ip,
            "AUTH_LOGON_PROOF_C",
            StepResult.SUCCESS,
            auth_failed=False,
            now=float(attempt),
        )

    assert AUTH_RATE_LIMIT.get(ip) is None
    assert auth_rate_limit_exceeded(ip, now=100.0) is False


def test_repeated_invalid_passwords_still_trigger_rate_limit():
    ip = "192.0.2.11"
    AUTH_RATE_LIMIT.pop(ip, None)

    for attempt in range(AUTH_RATE_MAX):
        apply_auth_rate_result(
            ip,
            "AUTH_LOGON_PROOF_C",
            StepResult.SUCCESS,
            auth_failed=True,
            now=float(attempt),
        )

    assert len(AUTH_RATE_LIMIT[ip]) == AUTH_RATE_MAX
    assert auth_rate_limit_exceeded(ip, now=float(AUTH_RATE_MAX)) is True


def test_successful_login_resets_previous_failures():
    ip = "192.0.2.12"
    AUTH_RATE_LIMIT[ip] = [1.0, 2.0, 3.0]

    apply_auth_rate_result(
        ip,
        "AUTH_LOGON_PROOF_C",
        StepResult.SUCCESS,
        auth_failed=False,
        now=4.0,
    )

    assert AUTH_RATE_LIMIT.get(ip) is None
    assert auth_rate_limit_exceeded(ip, now=4.0) is False


def test_realm_list_and_successful_reconnect_do_not_accumulate_failures():
    ip = "192.0.2.13"
    AUTH_RATE_LIMIT[ip] = [1.0, 2.0]

    apply_auth_rate_result(
        ip,
        "REALM_LIST_C",
        StepResult.SUCCESS,
        auth_failed=False,
        now=3.0,
    )
    assert AUTH_RATE_LIMIT[ip] == [1.0, 2.0]

    apply_auth_rate_result(
        ip,
        "AUTH_RECONNECT_CHALLENGE_C",
        StepResult.SUCCESS,
        auth_failed=False,
        now=4.0,
    )
    assert AUTH_RATE_LIMIT.get(ip) is None


def test_realm_list_size_counts_payload_after_three_byte_header():
    packet = build_REALM_LIST_S([
        {
            "icon": 0,
            "lock": 0,
            "flag": 0x20,
            "name": "PyPandaria",
            "address": "192.168.11.30:8085",
            "pop": 0.0,
            "characters": 0,
            "timezone": 1,
            "realmid": 1,
        }
    ])

    assert packet[0] == 0x10
    assert len(packet) == 51
    assert packet[1:3] == b"\x30\x00"
    assert struct.unpack_from("<H", packet, 1)[0] == len(packet) - 3


def test_step_controller_success_advances_state():
    ctx = _packet("AUTH_LOGON_CHALLENGE_C", {"I": "TEST"})
    conn = ConnectionContext(start_time=time.time())

    try:
        result, response = step_controller(conn, lambda packet_ctx: (0, b"\x00"), ctx)
    finally:
        ctx.sock.close()

    assert result == StepResult.SUCCESS
    assert response == b"\x00"
    assert conn.state == "AUTH_LOGON_PROOF"
    assert conn.retry_count == 0


def test_step_controller_invalid_resets_to_initial_state():
    ctx = _packet("AUTH_LOGON_CHALLENGE_C", {})
    conn = ConnectionContext(state="AUTH_LOGON_PROOF", start_time=time.time())

    try:
        result, response = step_controller(conn, lambda packet_ctx: (0, b"\x00"), ctx)
    finally:
        ctx.sock.close()

    assert result == StepResult.INVALID
    assert response is None
    assert conn.state == INITIAL_STATE


def test_step_controller_retries_once_then_rolls_back():
    ctx = _packet("AUTH_LOGON_PROOF_C", {"A": "aa", "M1": "bb"})
    conn = ConnectionContext(state="AUTH_LOGON_PROOF", start_time=time.time())

    try:
        first_result, _ = step_controller(conn, lambda packet_ctx: (1, None), ctx)
        second_result, _ = step_controller(conn, lambda packet_ctx: (1, None), ctx)
    finally:
        ctx.sock.close()

    assert first_result == StepResult.FAIL
    assert conn.retry_count == 0
    assert second_result == StepResult.FAIL
    assert conn.state == "AUTH_LOGON_CHALLENGE"


def test_step_controller_proof_failure_with_response_resets_to_initial():
    ctx = _packet("AUTH_LOGON_PROOF_C", {"A": "aa", "M1": "bb"})
    conn = ConnectionContext(
        state="AUTH_LOGON_PROOF",
        start_time=time.time(),
        username="MAPE",
    )

    try:
        result, response = step_controller(conn, lambda packet_ctx: (1, b"\x01"), ctx)
    finally:
        ctx.sock.close()

    assert result == StepResult.FAIL
    assert response == b"\x01"
    assert conn.state == INITIAL_STATE
    assert conn.retry_count == 0
    assert conn.username is None


def test_step_controller_times_out_connection():
    ctx = _packet("REALM_LIST_C", {})
    conn = ConnectionContext(start_time=(time.time() - 10.0))

    try:
        result, response = step_controller(conn, lambda packet_ctx: (0, b"\x00"), ctx)
    finally:
        ctx.sock.close()

    assert result == StepResult.TIMEOUT
    assert response is None
