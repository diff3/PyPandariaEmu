#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import signal
import socket
import threading
import time
import traceback

from dataclasses import dataclass
from enum import Enum

import server.session.auth_cache as auth_cache
from DSL.modules.DslRuntime import DslRuntime
from server.modules.crypto.SRP6Session import SRP6Session
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.handlers.AuthHandlers import opcode_handlers, set_srp6_mode
from server.modules.opcodes.AuthOpcodes import (
    AUTH_CLIENT_OPCODES,
    AUTH_SERVER_OPCODES,
)
from server.modules.protocol.PacketContext import PacketContext
from server.modules.protocol.ServerOutput import (
    decode_enabled,
    dsl_warnings_enabled,
    log_decoded_packet,
    log_raw_packet,
    project_name,
    should_log_packet,
)
from shared.ConfigLoader import ConfigLoader
from shared.Logger import Logger


AUTH_DEFS = [
    "AUTH_LOGON_CHALLENGE_C",
    "AUTH_LOGON_CHALLENGE_S",
    "AUTH_LOGON_CHALLENGE_S_FAILURE",
    "AUTH_LOGON_PROOF_C",
    "AUTH_LOGON_PROOF_S",
    "AUTH_LOGON_PROOF_S_FAILURE",
    "REALM_LIST_C",
    "REALM_LIST_S",
    "AUTH_RECONNECT_CHALLENGE_C",
    "AUTH_RECONNECT_CHALLENGE_S",
]

MAX_CONNECTION_TIME_SECONDS = 15.0
REALM_LIST_CONNECTION_TIME_SECONDS = 300.0
MAX_CONNECTION_STEPS = 20

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
config = ConfigLoader.load_config()
HOST = config["authserver"]["host"]
PORT = config["authserver"]["port"]

running = True
runtime = None
AUTH_RATE_LIMIT = {}
AUTH_RATE_WINDOW = 10
AUTH_RATE_MAX = 5
RATE_LIMIT_LOCK = threading.Lock()
MAX_CONNECTIONS = config["authserver"].get("max_connections", 100)
ACTIVE_CONNECTIONS = {"count": 0}
CONNECTION_LOCK = threading.Lock()


class StepResult(str, Enum):
    SUCCESS = "SUCCESS"
    FAIL = "FAIL"
    INVALID = "INVALID"
    TIMEOUT = "TIMEOUT"
    FATAL = "FATAL"


FAILURE_RESULTS = frozenset(
    (
        StepResult.FAIL,
        StepResult.FATAL,
        StepResult.INVALID,
        StepResult.TIMEOUT,
    )
)


def validate_logon(decoded: dict) -> bool:
    return extract_username(decoded) is not None


def validate_proof(decoded: dict) -> bool:
    return bool(decoded.get("A") and decoded.get("M1"))


def extract_username(decoded: dict) -> str | None:
    value = str(decoded.get("I") or decoded.get("username") or "")
    value = value.strip().upper()
    return value or None


VALIDATORS = {
    "AUTH_LOGON_CHALLENGE_C": validate_logon,
    "AUTH_LOGON_PROOF_C": validate_proof,
}
VALIDATION_ERRORS = {
    "AUTH_LOGON_CHALLENGE_C": "missing username",
    "AUTH_LOGON_PROOF_C": "missing proof values",
}


@dataclass
class ConnectionContext:
    state: str = INITIAL_STATE
    retry_count: int = 0
    step_count: int = 0
    start_time: float = 0.0
    last_error: str | None = None
    username: str | None = None
    srp_session: SRP6Session | None = None
    auth_failed: bool = False
    last_auth_failed: bool = False


def _prune_auth_failures(ip: str, now: float) -> list[float]:
    bucket = [
        timestamp
        for timestamp in AUTH_RATE_LIMIT.get(str(ip), [])
        if float(now) - float(timestamp) < AUTH_RATE_WINDOW
    ]
    if bucket:
        AUTH_RATE_LIMIT[str(ip)] = bucket
    else:
        AUTH_RATE_LIMIT.pop(str(ip), None)
    return bucket


def auth_rate_limit_exceeded(ip: str, *, now: float | None = None) -> bool:
    current_time = time.time() if now is None else float(now)
    with RATE_LIMIT_LOCK:
        return len(_prune_auth_failures(str(ip), current_time)) >= AUTH_RATE_MAX


def record_auth_failure(ip: str, *, now: float | None = None) -> None:
    current_time = time.time() if now is None else float(now)
    with RATE_LIMIT_LOCK:
        bucket = _prune_auth_failures(str(ip), current_time)
        before = len(bucket)
        bucket.append(current_time)
        AUTH_RATE_LIMIT[str(ip)] = bucket
        after = len(bucket)
    Logger.debug(
        "[AUTH_RATE] failed login ip=%s counter_before=%s counter_after=%s",
        ip,
        before,
        after,
    )


def reset_auth_failures(ip: str) -> None:
    with RATE_LIMIT_LOCK:
        before = len(AUTH_RATE_LIMIT.get(str(ip), []))
        AUTH_RATE_LIMIT.pop(str(ip), None)
    Logger.debug(
        "[AUTH_RATE] successful login ip=%s counter_before=%s counter_after=0",
        ip,
        before,
    )


def apply_auth_rate_result(
    ip: str,
    opcode_name: str,
    result: StepResult,
    *,
    auth_failed: bool,
    now: float | None = None,
) -> None:
    if bool(auth_failed) or result in FAILURE_RESULTS:
        record_auth_failure(ip, now=now)
        return

    if result == StepResult.SUCCESS and opcode_name in (
        "AUTH_LOGON_PROOF_C",
        "AUTH_RECONNECT_CHALLENGE_C",
    ):
        reset_auth_failures(ip)


def next_state(state: str) -> str:
    try:
        index = STATE_FLOW.index(str(state))
    except ValueError:
        return INITIAL_STATE

    if index >= len(STATE_FLOW) - 1:
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


def terminate_connection(
    sock: socket.socket,
    conn_ctx: ConnectionContext,
    reason: str,
) -> None:
    if conn_ctx.last_error != reason:
        conn_ctx.last_error = reason
        Logger.warning(
            "[AuthServer] terminate state=%s user=%s reason=%s",
            conn_ctx.state,
            conn_ctx.username,
            reason,
        )

    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


def pre_check(
    conn_ctx: ConnectionContext,
    packet_ctx: PacketContext,
) -> StepResult:
    now = time.time()
    time_limit = connection_time_limit_for_state(conn_ctx.state)

    if now - float(conn_ctx.start_time or now) > time_limit:
        conn_ctx.last_error = "connection exceeded time limit"
        Logger.warning(
            "[TIMEOUT] connection exceeded limit state=%s limit=%s",
            conn_ctx.state,
            time_limit,
        )
        return StepResult.TIMEOUT

    conn_ctx.step_count += 1

    if conn_ctx.step_count > MAX_CONNECTION_STEPS:
        conn_ctx.last_error = "step limit exceeded"
        Logger.warning(
            "[TIMEOUT] step limit exceeded state=%s steps=%s",
            conn_ctx.state,
            conn_ctx.step_count,
        )
        return StepResult.TIMEOUT

    opcode_name = str(packet_ctx.name or "")
    decoded = dict(packet_ctx.decoded or {})
    validator = VALIDATORS.get(opcode_name)

    if validator is not None and not validator(decoded):
        conn_ctx.last_error = VALIDATION_ERRORS.get(
            opcode_name,
            "packet validation failed",
        )
        Logger.warning(
            "[FSM] INVALID state=%s reason=%s",
            conn_ctx.state,
            conn_ctx.last_error,
        )
        return StepResult.INVALID

    expected_state = STATE_BY_OPCODE.get(opcode_name)
    if expected_state:
        previous = previous_state(expected_state)
        if conn_ctx.state not in (expected_state, previous):
            conn_ctx.last_error = (
                f"unexpected opcode for state={conn_ctx.state}"
            )
            Logger.warning(
                "[FSM] INVALID state=%s reason=%s",
                conn_ctx.state,
                conn_ctx.last_error,
            )
            return StepResult.INVALID

    return StepResult.SUCCESS


def post_check(
    conn_ctx: ConnectionContext,
    packet_ctx: PacketContext,
    handler_error: int,
) -> StepResult:
    current_state = conn_ctx.state
    expected_state = STATE_BY_OPCODE.get(packet_ctx.name, current_state)

    if int(handler_error or 0) != 0:
        conn_ctx.last_error = f"handler returned err={handler_error}"
        Logger.warning(
            "[FSM] FAIL state=%s opcode=%s reason=%s",
            current_state,
            packet_ctx.name,
            conn_ctx.last_error,
        )
        return StepResult.FAIL

    if conn_ctx.auth_failed:
        Logger.debug(
            "[FSM] %s + AUTH_FAIL -> %s",
            current_state,
            INITIAL_STATE,
        )
        conn_ctx.state = INITIAL_STATE
        conn_ctx.retry_count = 0
        conn_ctx.auth_failed = False
        return StepResult.SUCCESS

    next_logical_state = next_state(expected_state or current_state)

    Logger.debug(
        "[FSM] %s + SUCCESS -> %s",
        current_state,
        next_logical_state,
    )

    conn_ctx.state = next_logical_state
    conn_ctx.last_error = None
    return StepResult.SUCCESS


def sigint(_sig, _frame) -> None:
    global running

    Logger.info("Shutting down AuthServer (Ctrl+C)...")
    running = False


def safe_decode(direction: str, name: str, payload: bytes) -> dict:
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
        Logger.error("%s: decode failed for %s: %s", direction, name, exc)
        Logger.error(traceback.format_exc())
        return {}


def log_client_packet(opcode_name: str, data: bytes, decoded: dict) -> None:
    if should_log_packet("authserver", opcode_name):
        Logger.debug("[AuthServer] C->S %s", opcode_name)

    log_raw_packet("authserver", opcode_name, "Raw", data)
    log_decoded_packet(
        "authserver",
        opcode_name,
        decoded,
        label=opcode_name,
    )


def step_controller(
    conn_ctx: ConnectionContext,
    handler,
    packet_ctx: PacketContext,
) -> tuple[StepResult, bytes | None]:
    packet_ctx.connection_ctx = conn_ctx

    step_result = pre_check(conn_ctx, packet_ctx)
    if step_result != StepResult.SUCCESS:
        if step_result == StepResult.INVALID:
            conn_ctx.state = INITIAL_STATE
        return step_result, None

    try:
        handler_error, response = handler(packet_ctx)
    except Exception as exc:
        conn_ctx.last_error = str(exc)
        Logger.error(
            "[FATAL] state=%s opcode=%s error=%s",
            conn_ctx.state,
            packet_ctx.name,
            exc,
        )
        Logger.error(traceback.format_exc())
        return StepResult.FATAL, None

    step_result = post_check(conn_ctx, packet_ctx, handler_error)
    return step_result, response


def process_packet(
    conn_ctx: ConnectionContext,
    data: bytes,
    sock: socket.socket,
) -> tuple[StepResult, bytes | None]:
    conn_ctx.last_auth_failed = False
    if not data:
        conn_ctx.last_error = "empty packet"
        Logger.warning("[AuthServer] empty client packet")
        return StepResult.INVALID, None

    opcode = data[0]
    opcode_name = AUTH_CLIENT_OPCODES.get(opcode)

    if opcode_name is None:
        conn_ctx.last_error = f"unknown opcode 0x{opcode:02X}"
        Logger.warning("[AuthServer] %s", conn_ctx.last_error)
        return StepResult.INVALID, None

    decoded = safe_decode("Client", opcode_name, data)
    log_client_packet(opcode_name, data, decoded)

    handler = opcode_handlers.get(opcode_name)
    if handler is None:
        conn_ctx.last_error = f"missing handler for {opcode_name}"
        Logger.warning("[AuthServer] %s", conn_ctx.last_error)
        return StepResult.INVALID, None

    packet_ctx = PacketContext(
        sock=sock,
        direction="C",
        opcode=opcode,
        name=opcode_name,
        payload=data,
        decoded=decoded,
        connection_ctx=conn_ctx,
    )

    step_result = pre_check(conn_ctx, packet_ctx)
    if step_result != StepResult.SUCCESS:
        return step_result, None

    try:
        handler_error, response = handler(packet_ctx)
    except Exception as exc:
        conn_ctx.last_error = str(exc)

        Logger.error(
            "[FATAL] state=%s opcode=%s error=%s",
            conn_ctx.state,
            packet_ctx.name,
            exc,
        )
        Logger.error(traceback.format_exc())

        return StepResult.FATAL, None

    conn_ctx.last_auth_failed = bool(conn_ctx.auth_failed)
    username = extract_username(decoded)
    if username and not conn_ctx.auth_failed:
        conn_ctx.username = username

    step_result = post_check(conn_ctx, packet_ctx, handler_error)
    return step_result, response


def resolve_server_packet_name(response: bytes) -> str | None:
    if not response:
        return None

    opcode = response[0]

    if opcode == 0x00 and len(response) == 3:
        return "AUTH_LOGON_CHALLENGE_S_FAILURE"

    if opcode == 0x01 and len(response) == 4:
        return "AUTH_LOGON_PROOF_S_FAILURE"

    return AUTH_SERVER_OPCODES.get(opcode)


def send_server_response(
    sock: socket.socket,
    conn_ctx: ConnectionContext,
    addr: tuple[str, int],
    response: bytes,
) -> str | None:
    if not response:
        conn_ctx.last_error = "empty server response"
        Logger.error("[AuthServer] empty server response addr=%s", addr)
        return None

    server_opcode = response[0]
    server_name = resolve_server_packet_name(response)

    if not server_name:
        reason = f"invalid server opcode 0x{server_opcode:02X}"
        conn_ctx.last_error = reason
        Logger.error("[AuthServer] %s addr=%s", reason, addr)
        return None

    server_logging_enabled = should_log_packet(
        "authserver",
        server_name,
    )

    if server_logging_enabled:
        Logger.debug("[AuthServer] S->C %s", server_name)

    log_raw_packet(
        "authserver",
        server_name,
        "Raw",
        response,
    )

    if server_logging_enabled and decode_enabled("authserver"):
        decoded = safe_decode("Server", server_name, response)
        log_decoded_packet(
            "authserver",
            server_name,
            decoded,
            label=server_name,
        )

    try:
        sock.sendall(response)
    except OSError as exc:
        conn_ctx.last_error = f"send failed: {exc}"
        Logger.error("[AuthServer] %s addr=%s", conn_ctx.last_error, addr)
        return None

    if server_name == "REALM_LIST_S":
        conn_ctx.last_error = None
        timeout = connection_time_limit_for_state(conn_ctx.state)
        sock.settimeout(timeout)

        Logger.debug(
            "[AuthServer] realm list ready addr=%s timeout=%s",
            addr,
            timeout,
        )

    return server_name


def handle_client(sock: socket.socket, addr: tuple[str, int]) -> None:
    Logger.info("Connection start addr=%s", addr)

    conn_ctx = ConnectionContext(start_time=time.time())
    sock.settimeout(MAX_CONNECTION_TIME_SECONDS)

    try:
        while True:
            try:
                data = sock.recv(1024)
            except socket.timeout:
                if conn_ctx.state == "REALM_LIST":
                    conn_ctx.last_error = None
                    Logger.debug(
                        "[AuthServer] auth flow complete addr=%s state=%s",
                        addr,
                        conn_ctx.state,
                    )
                    break

                terminate_connection(sock, conn_ctx, "idle timeout")
                return

            if not data:
                Logger.info(
                    "Connection closed addr=%s state=%s",
                    addr,
                    conn_ctx.state,
                )
                break

            ip = addr[0]
            if auth_rate_limit_exceeded(ip):
                Logger.warning("[AUTH] rate limit exceeded ip=%s", ip)
                terminate_connection(sock, conn_ctx, "rate limit")
                return

            opcode_name = AUTH_CLIENT_OPCODES.get(data[0]) if data else None
            result, response = process_packet(conn_ctx, data, sock)
            apply_auth_rate_result(
                ip,
                str(opcode_name or ""),
                result,
                auth_failed=conn_ctx.last_auth_failed,
            )

            if response:
                server_name = send_server_response(
                    sock,
                    conn_ctx,
                    addr,
                    response,
                )
                if server_name is None:
                    terminate_connection(sock, conn_ctx, "server send failed")
                    return

            if result in FAILURE_RESULTS:
                terminate_connection(
                    sock,
                    conn_ctx,
                    conn_ctx.last_error or f"auth failed result={result.value}",
                )
                return

    except Exception as exc:
        Logger.error("%s: unexpected error: %s", addr, exc)
        Logger.error(traceback.format_exc())
        terminate_connection(sock, conn_ctx, f"unexpected error: {exc}")

    finally:
        Logger.info(
            "[AuthServer] connection stop addr=%s state=%s steps=%s "
            "username=%s error=%s",
            addr,
            conn_ctx.state,
            conn_ctx.step_count,
            conn_ctx.username,
            conn_ctx.last_error,
        )

        try:
            sock.close()
        except OSError:
            pass

        with CONNECTION_LOCK:
            ACTIVE_CONNECTIONS["count"] = max(
                0,
                ACTIVE_CONNECTIONS["count"] - 1,
            )


def start_server() -> None:
    global running

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(5)
    server_sock.settimeout(1.0)

    Logger.success("AuthServer listening on %s:%s", HOST, PORT)

    try:
        while running:
            try:
                client_sock, addr = server_sock.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                Logger.error("Server accept error: %s", exc)
                Logger.error(traceback.format_exc())
                continue

            with CONNECTION_LOCK:
                if ACTIVE_CONNECTIONS["count"] >= MAX_CONNECTIONS:
                    Logger.warning(
                        "[AuthServer] connection refused "
                        "(limit reached) addr=%s",
                        addr,
                    )
                    client_sock.close()
                    continue

                ACTIVE_CONNECTIONS["count"] += 1

            threading.Thread(
                target=handle_client,
                args=(client_sock, addr),
                daemon=True,
            ).start()
    finally:
        Logger.info("AuthServer stopping...")
        server_sock.close()


def preload_account_cache() -> None:
    try:
        accounts = DatabaseConnection.get_all_auth_accounts()
        new_cache = {}

        for account in accounts:
            username = str(account.username or "").strip().upper()
            if not username:
                continue

            new_cache[username] = {
                "id": account.id,
                "username": username,
                "salt": bytes(account.salt or b""),
                "verifier": bytes(account.verifier or b""),
            }

        with auth_cache.ACCOUNT_CACHE_LOCK:
            auth_cache.ACCOUNT_CACHE.clear()
            auth_cache.ACCOUNT_CACHE.update(new_cache)

        Logger.info(
            "Account cache loaded (%s accounts)",
            len(new_cache),
        )
    except Exception as exc:
        Logger.error("Account cache preload failed: %s", exc)
        Logger.error(traceback.format_exc())
        raise


def run_auth() -> None:
    global runtime

    Logger.configure(scope="dsl", reset=True)
    Logger.configure(scope="authserver", reset=True)

    signal.signal(signal.SIGINT, sigint)
    signal.signal(signal.SIGTERM, sigint)

    Logger.info("%s AuthServer", project_name())

    DatabaseConnection.initialize_auth()
    DatabaseConnection.initialize_characters()
    preload_account_cache()

    set_srp6_mode(config.get("crypto", {}).get("srp6_mode", "skyfire"))

    try:
        runtime = DslRuntime(watch=False)
        loaded, total = runtime.load_runtime_selected(
            AUTH_DEFS,
            progress=True,
        )
    except Exception as exc:
        Logger.error("[AuthServer] Runtime init failed: %s", exc)
        Logger.error(traceback.format_exc())
        raise

    pct = int((loaded * 100 / total)) if total else 0
    Logger.info("DSL runtime ready [%s/%s] %s%%", loaded, total, pct)

    start_server()


if __name__ == "__main__":
    run_auth()
