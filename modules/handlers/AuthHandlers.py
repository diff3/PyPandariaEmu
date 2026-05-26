#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SRP6-based authentication handling for MoP 5.4.8.

Handles:
    • AUTH_LOGON_CHALLENGE_C
    • AUTH_LOGON_PROOF_C
    • REALM_LIST_C
    • AUTH_RECONNECT_CHALLENGE_C

Used by AuthServer to process DSL-decoded packets.
"""

import os
import socket
import threading
import time
import traceback

from shared.Logger import Logger
from server.modules.protocol.PacketContext import PacketContext
# from server.modules.opcodes.OpcodeLoader import load_auth_opcodes
from server.modules.opcodes.AuthOpcodes import (
    AUTH_SERVER_OPCODES,
)
from DSL.modules.EncoderHandler import EncoderHandler

from server.modules.crypto.SRP6Session import SRP6Session
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.session.auth_cache import ACCOUNT_CACHE, ACCOUNT_CACHE_LOCK

# ---- Global state ---------------------------------------------------------

# srp6_sessions: dict[int, SRP6Session] = {}
# authenticated_users: dict[int, str] = {}

# Opcode maps: int → name (per direction) + reverse for convenience
# AUTH_CLIENT_OPCODES, AUTH_SERVER_OPCODES, _ = load_auth_opcodes()
AUTH_SERVER_OPCODE_BY_NAME = {
    name: code for code, name in AUTH_SERVER_OPCODES.items()
}
_srp6_mode = "skyfire"
WOW_SUCCESS = 0x00
WOW_FAIL_UNKNOWN_ACCOUNT = 0x04
AUTH_LOGON_PROOF_ERROR_GENERIC = WOW_FAIL_UNKNOWN_ACCOUNT
ACCOUNT_FLAGS_PRO_PASS = 0x00800000
REALM_CACHE = {}
REALM_CACHE_TS = 0.0
REALM_CACHE_TTL = 5.0
REALM_STATUS = {}
REALM_STATUS_TS = 0.0
REALM_STATUS_TTL = 5.0
REALM_LOCK = threading.Lock()


def set_srp6_mode(mode: str) -> None:
    global _srp6_mode
    _srp6_mode = str(mode or "skyfire")


def extract_username(decoded: dict) -> str | None:
    value = str(decoded.get("I") or decoded.get("username") or "")
    value = value.strip().upper()
    return value or None


def reset_auth_state(conn_ctx):
    conn_ctx.srp_session = None
    conn_ctx.username = None


def mark_auth_failure(conn_ctx, reason: str) -> None:
    reset_auth_state(conn_ctx)
    conn_ctx.auth_failed = True
    conn_ctx.last_error = reason


def log_auth_failure_packet(packet_name: str, data: bytes) -> None:
    Logger.debug(
        "[AUTH_FAIL_PACKET] name=%s length=%s hex=%s",
        packet_name,
        len(data),
        data.hex().upper(),
    )


def get_remote_ip(sock) -> str:
    try:
        return str(sock.getpeername()[0])
    except Exception:
        return "unknown"


def normalize_account(account) -> dict | None:
    if account is None:
        return None

    username = str(getattr(account, "username", "") or "").strip().upper()
    if not username:
        return None

    return {
        "id": getattr(account, "id", None),
        "username": username,
        "salt": bytes(getattr(account, "salt", b"") or b""),
        "verifier": bytes(getattr(account, "verifier", b"") or b""),
        "session_key": getattr(account, "session_key", None),
    }


def get_account(username: str) -> dict | None:
    username = str(username or "").strip().upper()
    if not username:
        return None

    with ACCOUNT_CACHE_LOCK:
        account = ACCOUNT_CACHE.get(username)
    if account:
        return account

    try:
        db_account = DatabaseConnection.get_user_by_username(username)
    except Exception as exc:
        Logger.error("[AUTH] DB lookup failed: %s", exc)
        return None

    account = normalize_account(db_account)
    if account is None:
        return None

    with ACCOUNT_CACHE_LOCK:
        ACCOUNT_CACHE[username] = account

    return account


def update_account_login(account_id, session_key, client_ip) -> None:
    if account_id is None:
        raise ValueError("missing account_id")

    session = DatabaseConnection.auth()
    try:
        from datetime import datetime
        from server.modules.database.AuthModel import Account

        db_account = session.query(Account).filter(
            Account.id == account_id
        ).first()

        if not db_account:
            raise RuntimeError(f"account not found: {account_id}")

        db_account.session_key = session_key
        db_account.last_login = datetime.utcnow()
        db_account.last_ip = client_ip

        session.commit()

    except Exception as exc:
        session.rollback()
        Logger.error("[AUTH] update_account_login failed: %s", exc)
        Logger.error(traceback.format_exc())
        raise


# ---- AUTH_LOGON_CHALLENGE ----------------------------------------------

def handle_AUTH_LOGON_CHALLENGE_C(ctx: PacketContext):
    decoded = ctx.decoded or {}
    conn_ctx = ctx.connection_ctx

    username = extract_username(decoded)

    if not username:
        mark_auth_failure(conn_ctx, "missing username")

        return 0, build_AUTH_LOGON_CHALLENGE_S_FAILURE()

    account = get_account(username)

    if account is None:
        mark_auth_failure(conn_ctx, "unknown account")

        return 0, build_AUTH_LOGON_CHALLENGE_S_FAILURE()

    salt = account["salt"]
    verifier = account["verifier"]

    if not salt or not verifier:
        mark_auth_failure(conn_ctx, "missing srp verifier")

        return 0, build_AUTH_LOGON_CHALLENGE_S_FAILURE()

    # Always create a fresh SRP session per connection
    session = SRP6Session(
        username,
        salt,
        verifier,
        mode=_srp6_mode,
    )

    conn_ctx.srp_session = session
    conn_ctx.username = username

    try:
        B_bytes = session.generate_B()

    except Exception as exc:
        Logger.error(
            "[AUTH_LOGON_CHALLENGE] SRP6 generate_B failed: %s",
            exc,
        )

        conn_ctx.srp_session = None
        conn_ctx.auth_failed = True
        conn_ctx.last_error = "srp challenge failed"

        return 0, build_AUTH_LOGON_CHALLENGE_S_FAILURE()

    fields = {
        "cmd": 0,
        "error": 0,
        "success": 0,
        "B": B_bytes,
        "l": 1,
        "g": session.core.G,
        "blob": 32,
        "N": session.core.get_N_bytes(),
        "s": salt,
        "unk3": os.urandom(16),
        "securityFlags": 0,
    }

    try:
        return 0, build_AUTH_LOGON_CHALLENGE_S(fields)

    except Exception:
        conn_ctx.srp_session = None
        return 1, None


def build_AUTH_LOGON_CHALLENGE_S(fields: dict) -> bytes:
    """
    Encode AUTH_LOGON_CHALLENGE_S using provided fields.
    Keeps handling logic separate from encoding for reuse and clarity.
    """
    return EncoderHandler.encode_packet("AUTH_LOGON_CHALLENGE_S", fields)


def build_AUTH_LOGON_CHALLENGE_S_FAILURE(
    result: int = WOW_FAIL_UNKNOWN_ACCOUNT,
) -> bytes:
    fields = {
        "cmd": 0,
        "error": WOW_SUCCESS,
        "result": int(result),
    }

    out = EncoderHandler.encode_packet(
        "AUTH_LOGON_CHALLENGE_S_FAILURE",
        fields,
    )
    log_auth_failure_packet("AUTH_LOGON_CHALLENGE_S_FAILURE", out)
    return out


# ---- AUTH_LOGON_PROOF --------------------------------------------------

def handle_AUTH_LOGON_PROOF_C(ctx: PacketContext):
    decoded = ctx.decoded or {}
    conn_ctx = ctx.connection_ctx

    session = conn_ctx.srp_session

    if not session:
        Logger.error(
            "[AUTH_LOGON_PROOF] No SRP session for connection"
        )
        mark_auth_failure(conn_ctx, "missing srp session")

        return 0, build_AUTH_LOGON_PROOF_S_FAILURE()

    A_raw = decoded.get("A")
    M1_raw = decoded.get("M1")

    try:
        A = bytes.fromhex(A_raw) if isinstance(A_raw, str) else A_raw
        M1 = bytes.fromhex(M1_raw) if isinstance(M1_raw, str) else M1_raw

    except ValueError:
        Logger.error(
            "[AUTH_LOGON_PROOF] Invalid hex in A or M1"
        )

        conn_ctx.srp_session = None
        conn_ctx.auth_failed = True
        conn_ctx.last_error = "invalid proof hex"

        return 0, build_AUTH_LOGON_PROOF_S_FAILURE()

    if not A or not M1:
        Logger.error(
            "[AUTH_LOGON_PROOF] Missing A or M1"
        )

        conn_ctx.srp_session = None
        conn_ctx.auth_failed = True
        conn_ctx.last_error = "missing proof values"

        return 0, build_AUTH_LOGON_PROOF_S_FAILURE()

    ok, M2, session_key = session.verify_proof(A, M1)

    if not ok:
        Logger.error(
            "[AUTH_LOGON_PROOF] SRP proof failed"
        )
        Logger.warning(
            "[AUTH_FAIL] user=%s ip=%s reason=srp_failed",
            session.username,
            get_remote_ip(ctx.sock),
        )

        mark_auth_failure(conn_ctx, "srp proof failed")

        return 0, build_AUTH_LOGON_PROOF_S_FAILURE()

    try:
        account = get_account(session.username)
        if not account:
            mark_auth_failure(conn_ctx, "account missing during proof")
            return 0, build_AUTH_LOGON_PROOF_S_FAILURE()

        update_account_login(
            account.get("id"),
            session_key,
            get_remote_ip(ctx.sock),
        )

        account["session_key"] = session_key

    except Exception as exc:
        Logger.error(
            "[AUTH_LOGON_PROOF] Failed to update DB: %s",
            exc,
        )
        conn_ctx.srp_session = None
        return 1, None

    # Username already lives in conn_ctx
    conn_ctx.username = session.username

    try:
        fields = {
            "cmd": 1,
            "error": 0,
            "M2": M2,
            "unk1": ACCOUNT_FLAGS_PRO_PASS,
            "unk2": 0,
            "unk3": 0,
        }

        out = build_AUTH_LOGON_PROOF_S(fields)

    except Exception as exc:
        Logger.error(
            "[AUTH_LOGON_PROOF_S] Encoding failed: %s",
            exc,
        )

        conn_ctx.srp_session = None

        return 1, None

    # Cleanup temporary SRP state after success
    conn_ctx.srp_session = None

    return 0, out


def build_AUTH_LOGON_PROOF_S(fields: dict) -> bytes:
    """
    Encode AUTH_LOGON_PROOF_S using provided fields.
    """
    return EncoderHandler.encode_packet("AUTH_LOGON_PROOF_S", fields)


def build_AUTH_LOGON_PROOF_S_FAILURE(
    error: int = AUTH_LOGON_PROOF_ERROR_GENERIC,
) -> bytes:
    out = EncoderHandler.encode_packet(
        "AUTH_LOGON_PROOF_S_FAILURE",
        {
            "cmd": 1,
            "error": int(error),
            "unk1": 3,
            "unk2": 0,
        },
    )
    log_auth_failure_packet("AUTH_LOGON_PROOF_S_FAILURE", out)
    return out


# ---- REALM LIST ----------------------------------------------------------

def calculate_population(char_count: int) -> float:
    if char_count <= 0:
        return 0.05
    if char_count < 50:
        return 1.0
    if char_count < 200:
        return 2.0
    if char_count < 1000:
        return 3.0
    return 5.0


def is_realm_online(address: str, port: int) -> bool:
    try:
        with socket.create_connection((address, port), timeout=0.05):
            return True
    except Exception:
        return False


def realm_flag(online: bool) -> int:
    return 0 if online else 4


def get_realms():
    global REALM_CACHE_TS

    now = time.time()

    with REALM_LOCK:
        if REALM_CACHE and (now - REALM_CACHE_TS) < REALM_CACHE_TTL:
            return list(REALM_CACHE.values())

    realms = DatabaseConnection.get_all_realms()
    if not realms:
        return []

    new_cache = {realm.id: realm for realm in realms}

    with REALM_LOCK:
        REALM_CACHE.clear()
        REALM_CACHE.update(new_cache)
        REALM_CACHE_TS = now

    return list(new_cache.values())


def refresh_realm_status(realms):
    global REALM_STATUS_TS

    now = time.time()

    with REALM_LOCK:
        if (now - REALM_STATUS_TS) < REALM_STATUS_TTL:
            return

    new_status = {}

    for realm in realms:
        try:
            online = is_realm_online(realm.address, realm.port)
        except Exception:
            online = False

        new_status[realm.id] = online

    with REALM_LOCK:
        REALM_STATUS.clear()
        REALM_STATUS.update(new_status)
        REALM_STATUS_TS = now


def build_realmlist_entries(realms, account_id):
    refresh_realm_status(realms)

    entries = []
    char_counts = {}

    with REALM_LOCK:
        status_snapshot = dict(REALM_STATUS)

    for realm in realms:
        if account_id is None:
            char_count = 0
        else:
            char_count = char_counts.get(realm.id)
            if char_count is None:
                char_count = DatabaseConnection.count_characters_for_account(
                    account_id, realm.id
                )
                char_counts[realm.id] = char_count

        online = status_snapshot.get(realm.id, False)

        entries.append({
            "icon": realm.icon,
            "lock": 0 if online else 1,
            "flag": realm_flag(online),
            "name": realm.name,
            "address": f"{realm.address}:{realm.port}",
            "pop": 0.0,
            "characters": char_count,
            "timezone": realm.timezone,
            "realmid": realm.id,
        })

    return entries


def handle_REALM_LIST_C(ctx: PacketContext):
    conn_ctx = ctx.connection_ctx

    username = conn_ctx.username
    account_id = None

    if username:
        account = get_account(username)
        if not account:
            return 1, None

        account_id = account.get("id")
        if not account_id:
            return 1, None

    db_realms = get_realms()

    if not db_realms:
        Logger.error(
            "[REALM_LIST] No realms in DB"
        )
        return 1, None

    realm_entries = build_realmlist_entries(
        db_realms,
        account_id,
    )

    try:
        out = build_REALM_LIST_S(
            realm_entries
        )

        return 0, out

    except Exception as exc:
        Logger.error(
            "[REALM_LIST_S] Encoding failed: %s",
            exc,
        )

        Logger.error(
            traceback.format_exc()
        )

        return 1, None


def build_REALM_LIST_S(realm_entries) -> bytes:
    fields = {
        "cmd": 0x10,
        "size": 48,
        "unk1": 0,
        "realm_list_size": len(realm_entries),
        "realmlist": realm_entries,
        "unk2": 0x10,
        "unk3": 0x00,
    }
    return EncoderHandler.encode_packet("REALM_LIST_S", fields)


# ---- AUTH_RECONNECT_CHALLENGE -----------------------------------------

def handle_AUTH_RECONNECT_CHALLENGE_C(ctx: PacketContext):
    """
    Handle AUTH_RECONNECT_CHALLENGE_C.
    Input: client socket, opcode byte, raw payload.
    Output: (err, response_bytes) tuple built from DSL encoder.
    """
    try:
        out = build_AUTH_RECONNECT_CHALLENGE_S()
        return 0, out
    except Exception as exc:
        Logger.error(f"[AUTH_RECONNECT_CHALLENGE_S] Encode failed: {exc}")
        return 1, None


def build_AUTH_RECONNECT_CHALLENGE_S() -> bytes:
    """
    Build AUTH_RECONNECT_CHALLENGE_S packet.
    Input: none; uses os.urandom for two 16-byte fields, cmd fixed to 0x02.
    Output: raw bytes ready to send (header+payload per EncoderHandler).
    """
    fields = {
        "cmd": 0x02,
        "_1": 0,
        "reconnectProof": os.urandom(16),
        "_2": os.urandom(16),
    }

    return EncoderHandler.encode_packet("AUTH_RECONNECT_CHALLENGE_S", fields)


# ---- Opcode dispatch -----------------------------------------------------

opcode_handlers = {
    "AUTH_LOGON_CHALLENGE_C": handle_AUTH_LOGON_CHALLENGE_C,
    "AUTH_LOGON_PROOF_C": handle_AUTH_LOGON_PROOF_C,
    "REALM_LIST_C": handle_REALM_LIST_C,
    "AUTH_RECONNECT_CHALLENGE_C": handle_AUTH_RECONNECT_CHALLENGE_C,
}
