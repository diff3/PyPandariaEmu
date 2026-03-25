import socket
import time

from server.authserver import (
    ConnectionContext,
    INITIAL_STATE,
    StepResult,
    next_state,
    previous_state,
    step_controller,
)
from server.modules.PacketContext import PacketContext


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
