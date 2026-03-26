#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import signal
import traceback
import threading
import time

from dataclasses import dataclass
from enum import Enum

from DSL.modules.DslRuntime import DslRuntime
from shared.Logger import Logger
from shared.ConfigLoader import ConfigLoader
from server.modules.protocol.PacketContext import PacketContext
from server.modules.protocol.ServerOutput import (
    decode_enabled,
    dsl_warnings_enabled,
    project_name,
    log_decoded_packet,
    log_raw_packet,
    should_log_packet,
)

from server.modules.crypto.SRP6Session import SRP6Session
from server.modules.opcodes.AuthOpcodes import AUTH_CLIENT_OPCODES, AUTH_SERVER_OPCODES


config = ConfigLoader.load_config()
DatabaseConnection = None
AuthHandlersModule = None
AUTH_HANDLERS = {}
set_srp6_mode = None

HOST = config["authserver"]["host"]
PORT = config["authserver"]["port"]
running = True
runtime = None
MAX_CONNECTION_TIME_SECONDS = 5.0
REALM_LIST_CONNECTION_TIME_SECONDS = 300.0
MAX_CONNECTION_STEPS = 10
INITIAL_STATE = "AUTH_LOGON_CHALLENGE"
STATE_FLOW = (
    "AUTH_LOGON_CHALLENGE",
    "AUTH_LOGON_PROOF",
    "REALM_LIST",
)
STATE_BY_OPCODE = {
    "AUTH_LOGON_CHALLENGE_C": "AUTH_LOGON_CHALLENGE",
    "AUTH_LOGON_PROOF_C": "AUTH_LOGON_PROOF",
    "REALM_LIST_C": "REALM_LIST",
    "AUTH_RECONNECT_CHALLENGE_C": "AUTH_LOGON_CHALLENGE",
}


class StepResult(str, Enum):
    SUCCESS = "SUCCESS"
    FAIL = "FAIL"
    INVALID = "INVALID"
    TIMEOUT = "TIMEOUT"
    FATAL = "FATAL"


@dataclass
class ConnectionContext:
    """
    Explicit per-connection authentication state.

    Lives for the entire socket session and tracks flow-control data used by
    AuthServer. It does not change handler signatures; handlers still receive
    PacketContext, while AuthServer owns retries, rollback and termination.
    """

    state: str = INITIAL_STATE
    retry_count: int = 0
    step_count: int = 0
    start_time: float = 0.0
    last_error: str | None = None
    username: str | None = None
    srp_session: SRP6Session | None = None


def next_state(state: str) -> str:
    try:
        index = STATE_FLOW.index(str(state))
    except ValueError:
        return INITIAL_STATE
    if index >= (len(STATE_FLOW) - 1):
        return STATE_FLOW[-1]
    return STATE_FLOW[index + 1]


def previous_state(state: str) -> str:
    try:
        index = STATE_FLOW.index(str(state))
    except ValueError:
        return INITIAL_STATE
    if index <= 0:
        return INITIAL_STATE
    return STATE_FLOW[index - 1]


def connection_time_limit_for_state(state: str) -> float:
    if str(state or "") == "REALM_LIST":
        return REALM_LIST_CONNECTION_TIME_SECONDS
    return MAX_CONNECTION_TIME_SECONDS


def validate_packet(conn_ctx: ConnectionContext, packet_ctx: PacketContext) -> tuple[bool, str | None]:
    opcode_name = str(packet_ctx.name or "")
    decoded = dict(packet_ctx.decoded or {})

    if opcode_name == "AUTH_LOGON_CHALLENGE_C":
        username = str(decoded.get("I") or decoded.get("username") or "").strip()
        if not username:
            return False, "missing username"
    elif opcode_name == "AUTH_LOGON_PROOF_C":
        if not decoded.get("A") or not decoded.get("M1"):
            return False, "missing proof values"

    expected_state = STATE_BY_OPCODE.get(opcode_name)
    if expected_state and conn_ctx.state not in {expected_state, previous_state(expected_state)}:
        return False, f"unexpected opcode for state={conn_ctx.state}"

    return True, None


def _sync_connection_state(conn_ctx: ConnectionContext, packet_ctx: PacketContext) -> None:
    decoded = dict(packet_ctx.decoded or {})

    username = str(decoded.get("I") or decoded.get("username") or conn_ctx.username or "").strip().upper()
    if username:
        conn_ctx.username = username


def _reset_auth_flow(conn_ctx: ConnectionContext) -> None:
    """Reset connection flow to a clean logon-challenge start."""
    conn_ctx.state = INITIAL_STATE
    conn_ctx.retry_count = 0
    conn_ctx.username = None
    conn_ctx.srp_session = None


def step_controller(conn_ctx: ConnectionContext, handler, packet_ctx: PacketContext):
    """
    Execute one authenticated protocol step with explicit flow control.

    Inputs:
    - conn_ctx: connection lifetime state
    - handler: existing AuthHandler callable
    - packet_ctx: decoded packet wrapper passed through unchanged

    Returns:
    - (StepResult, response_bytes | None)

    Failure behavior:
    - INVALID resets to INITIAL_STATE
    - FAIL retries once, then rolls back one logical state
    - TIMEOUT/FATAL instruct the caller to terminate the connection
    """
    now = time.time()
    time_limit = connection_time_limit_for_state(conn_ctx.state)
    if (now - float(conn_ctx.start_time or now)) > time_limit:
        conn_ctx.last_error = "connection exceeded time limit"
        Logger.warning(
            "[TIMEOUT] connection exceeded limit state=%s limit=%s",
            conn_ctx.state,
            time_limit,
        )
        return StepResult.TIMEOUT, None

    conn_ctx.step_count += 1
    if conn_ctx.step_count > MAX_CONNECTION_STEPS:
        conn_ctx.last_error = "step limit exceeded"
        Logger.warning("[TIMEOUT] step limit exceeded state=%s steps=%s", conn_ctx.state, conn_ctx.step_count)
        return StepResult.TIMEOUT, None

    valid, validation_error = validate_packet(conn_ctx, packet_ctx)
    if not valid:
        previous = conn_ctx.state
        conn_ctx.state = INITIAL_STATE
        conn_ctx.retry_count = 0
        conn_ctx.last_error = validation_error
        Logger.warning(
            "[FSM] %s + INVALID -> %s reason=%s",
            previous,
            conn_ctx.state,
            validation_error,
        )
        return StepResult.INVALID, None

    current_state = conn_ctx.state
    expected_state = STATE_BY_OPCODE.get(packet_ctx.name, current_state)

    try:
        err, response = handler(packet_ctx)
    except Exception as exc:
        conn_ctx.last_error = str(exc)
        Logger.error("[FATAL] state=%s opcode=%s error=%s", current_state, packet_ctx.name, exc)
        Logger.error(traceback.format_exc())
        return StepResult.FATAL, None

    _sync_connection_state(conn_ctx, packet_ctx)

    if int(err or 0) == 0:
        next_logical_state = next_state(expected_state or current_state)
        Logger.debug("[FSM] %s + SUCCESS -> %s", current_state, next_logical_state)
        conn_ctx.state = next_logical_state
        conn_ctx.retry_count = 0
        conn_ctx.last_error = None
        return StepResult.SUCCESS, response

    conn_ctx.last_error = f"handler returned err={err}"
    if packet_ctx.name == "AUTH_LOGON_PROOF_C" and response:
        Logger.warning("[FSM] %s + FAIL -> %s reason=proof_failed_reset", current_state, INITIAL_STATE)
        _reset_auth_flow(conn_ctx)
        return StepResult.FAIL, response

    if conn_ctx.retry_count < 1:
        conn_ctx.retry_count += 1
        Logger.warning("[RETRY] %s (%s)", current_state, conn_ctx.retry_count)
        return StepResult.FAIL, response

    rollback_state = previous_state(current_state)
    Logger.warning("[ROLLBACK] %s -> %s", current_state, rollback_state)
    Logger.warning("[FSM] %s + FAIL -> %s", current_state, rollback_state)
    conn_ctx.state = rollback_state
    conn_ctx.retry_count = 0
    return StepResult.FAIL, response


# ---- Signal handling ----------------------------------------------------

def sigint(sig, frame):
    """Gracefully stop authserver on Ctrl+C."""
    global running
    Logger.info("Shutting down AuthServer (Ctrl+C)...")
    running = False


# ---- Utility helpers ----------------------------------------------------

def safe_decode(direction: str, name: str, payload: bytes) -> dict:
    """Decode DSL packets without crashing handler logic."""
    if runtime is None:
        return {}

    try:
        return runtime.decode(
            name,
            payload,
            silent=True,
            warn=dsl_warnings_enabled("authserver"),
        ) or {}
    except Exception as exc:
        Logger.error(f"{direction}: decode failed for {name}: {exc}")
        Logger.error(traceback.format_exc())
        return {}


# ---- Client session handler ---------------------------------------------

def handle_client(sock: socket.socket, addr: tuple[str, int]) -> None:
    """
    Handle one auth connection from recv through decode, validate, step control and send.

    Inputs:
    - sock: accepted client socket
    - addr: peer address tuple

    Outputs:
    - None. Responses are written directly to the socket.

    Failure behavior:
    - invalid packets reset logical state safely
    - timeout or fatal conditions terminate the connection
    - handler crashes do not propagate past the connection boundary
    """
    Logger.info("[AuthServer] connection start addr=%s", addr)
    conn_ctx = ConnectionContext(start_time=time.time())
    sock.settimeout(MAX_CONNECTION_TIME_SECONDS)

    try:
        while True:
            try:
                data = sock.recv(1024)
            except socket.timeout:
                if conn_ctx.state == "REALM_LIST":
                    conn_ctx.last_error = None
                    Logger.debug("[AuthServer] auth flow complete addr=%s state=%s", addr, conn_ctx.state)
                else:
                    conn_ctx.last_error = "idle timeout"
                    Logger.info("[AuthServer] idle timeout addr=%s state=%s", addr, conn_ctx.state)
                break

            if not data:
                Logger.info("[AuthServer] connection closed addr=%s state=%s", addr, conn_ctx.state)
                break

            opcode = data[0]
            opcode_name = AUTH_CLIENT_OPCODES.get(opcode)

            if opcode_name is None:
                Logger.warning(f"{addr}: Unknown opcode 0x{opcode:02X}")
                break

            packet_logging_enabled = should_log_packet("authserver", opcode_name)
            if packet_logging_enabled:
                Logger.info(f"[AuthServer] C→S {opcode_name}")
            log_raw_packet("authserver", opcode_name, "Raw", data)

            decoded = safe_decode("Client", opcode_name, data)
            log_decoded_packet("authserver", opcode_name, decoded, label=opcode_name)

            handler = AUTH_HANDLERS.get(opcode_name)
            if handler is None:
                Logger.warning(f"{addr}: No handler for {opcode_name}")
                break

            try:
                ctx = PacketContext(
                    sock=sock,
                    direction="C",
                    opcode=opcode,
                    name=opcode_name,
                    payload=data,
                    decoded=decoded,
                    connection_ctx=conn_ctx,
                )
                result, response = step_controller(conn_ctx, handler, ctx)
            except Exception as exc:
                conn_ctx.last_error = str(exc)
                Logger.error(f"{addr}: Step controller crash: {exc}")
                Logger.error(traceback.format_exc())
                break

            if result in {StepResult.TIMEOUT, StepResult.FATAL}:
                Logger.warning(
                    "[AuthServer] terminating addr=%s result=%s state=%s error=%s",
                    addr,
                    result.value,
                    conn_ctx.state,
                    conn_ctx.last_error,
                )
                break

            if result == StepResult.INVALID:
                continue

            if not response:
                Logger.info(
                    "[AuthServer] no response addr=%s result=%s state=%s",
                    addr,
                    result.value,
                    conn_ctx.state,
                )
                continue

            server_op = response[0]
            server_name = AUTH_SERVER_OPCODES.get(server_op)

            if server_name:
                server_logging_enabled = should_log_packet("authserver", server_name)
                if server_logging_enabled:
                    Logger.info(f"[AuthServer] S→C {server_name}")
                log_raw_packet("authserver", server_name, "Raw", response)
                if server_logging_enabled and decode_enabled("authserver"):
                    log_decoded_packet(
                        "authserver",
                        server_name,
                        safe_decode("Server", server_name, response),
                        label=server_name,
                    )

            try:
                sock.sendall(response)
            except Exception as exc:
                Logger.error(f"{addr}: Failed to send response: {exc}")
                break

            if server_name == "REALM_LIST_S":
                conn_ctx.last_error = None
                sock.settimeout(connection_time_limit_for_state(conn_ctx.state))
                Logger.debug(
                    "[AuthServer] auth flow ready for repeat realm list addr=%s timeout=%s",
                    addr,
                    connection_time_limit_for_state(conn_ctx.state),
                )

    except Exception as exc:
        Logger.error(f"{addr}: Unexpected error: {exc}")
        Logger.error(traceback.format_exc())

    finally:
        Logger.info(
            "[AuthServer] connection stop addr=%s state=%s steps=%s username=%s error=%s",
            addr,
            conn_ctx.state,
            conn_ctx.step_count,
            conn_ctx.username,
            conn_ctx.last_error,
        )
        sock.close()


# ---- Server loop --------------------------------------------------------

def start_server() -> None:
    global running

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(5)

    Logger.info(f"AuthServer listening on {HOST}:{PORT}")

    while running:
        try:
            srv.settimeout(1.0)
            sock, addr = srv.accept()
            threading.Thread(
                target=handle_client,
                args=(sock, addr),
                daemon=True,
            ).start()
        except socket.timeout:
            continue
        except Exception as exc:
            Logger.error(f"Server error: {exc}")
            Logger.error(traceback.format_exc())

    Logger.info("AuthServer stopping...")
    srv.close()


# ---- Main entry ---------------------------------------------------------

def run_auth():
    global runtime, DatabaseConnection, AuthHandlersModule, AUTH_HANDLERS, set_srp6_mode

    Logger.configure(scope="dsl", reset=True)
    Logger.configure(scope="authserver", reset=True)
    signal.signal(signal.SIGINT, sigint)
    signal.signal(signal.SIGTERM, sigint)
    Logger.info(f"{project_name()} AuthServer")
    from server.modules.database.DatabaseConnection import DatabaseConnection as _DatabaseConnection
    import server.modules.handlers.AuthHandlers as _AuthHandlersModule
    from server.modules.handlers.AuthHandlers import (
        opcode_handlers as _AUTH_HANDLERS,
        set_srp6_mode as _set_srp6_mode,
    )

    DatabaseConnection = _DatabaseConnection
    AuthHandlersModule = _AuthHandlersModule
    AUTH_HANDLERS = _AUTH_HANDLERS
    set_srp6_mode = _set_srp6_mode

    DatabaseConnection.initialize()
    set_srp6_mode(config.get("crypto", {}).get("srp6_mode", "skyfire"))

    try:
        runtime = DslRuntime(watch=False)
        loaded, total = runtime.load_runtime_all()
        pct = int((loaded * 100 / total)) if total else 0
        Logger.info(f"DSL runtime ready [{loaded}/{total}] {pct}%")
    except Exception as exc:
        Logger.error(f"[AuthServer] Runtime init failed: {exc}")
        Logger.error(traceback.format_exc())
        raise

    start_server()


if __name__ == "__main__":
    run_auth()
