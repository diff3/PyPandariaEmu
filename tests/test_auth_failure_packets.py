import socket

from server.authserver import ConnectionContext
from server.modules.handlers import AuthHandlers
from server.modules.protocol.PacketContext import PacketContext


class FailingSrpSession:
    username = "MAPE"

    def verify_proof(self, _a, _m1):
        return False, b"", b""


def test_auth_logon_challenge_failure_is_short_layout():
    out = AuthHandlers.build_AUTH_LOGON_CHALLENGE_S_FAILURE()

    assert out == bytes([0x00, 0x00, AuthHandlers.WOW_FAIL_UNKNOWN_ACCOUNT])
    assert len(out) == 3


def test_auth_logon_proof_failure_is_four_byte_layout():
    out = AuthHandlers.build_AUTH_LOGON_PROOF_S_FAILURE()

    assert out == bytes([0x01, AuthHandlers.WOW_FAIL_UNKNOWN_ACCOUNT, 0x03, 0x00])
    assert len(out) == 4


def test_auth_logon_proof_success_still_uses_full_layout():
    out = AuthHandlers.build_AUTH_LOGON_PROOF_S(
        {
            "cmd": 1,
            "error": 0,
            "M2": bytes(range(20)),
            "unk1": AuthHandlers.ACCOUNT_FLAGS_PRO_PASS,
            "unk2": 0,
            "unk3": 0,
        }
    )

    assert len(out) == 32
    assert out[0:2] == b"\x01\x00"
    assert out[22:26] == b"\x00\x00\x80\x00"


def test_wrong_password_returns_short_failure_packet():
    left, right = socket.socketpair()
    conn_ctx = ConnectionContext(
        username="MAPE",
        srp_session=FailingSrpSession(),
    )
    ctx = PacketContext(
        sock=right,
        direction="C",
        opcode=1,
        name="AUTH_LOGON_PROOF_C",
        payload=b"",
        decoded={
            "A": "01" * 32,
            "M1": "02" * 20,
        },
        connection_ctx=conn_ctx,
    )

    try:
        err, out = AuthHandlers.handle_AUTH_LOGON_PROOF_C(ctx)
    finally:
        left.close()
        right.close()

    assert err == 0
    assert out == bytes([0x01, AuthHandlers.WOW_FAIL_UNKNOWN_ACCOUNT, 0x03, 0x00])
    assert conn_ctx.srp_session is None
    assert conn_ctx.auth_failed is True
