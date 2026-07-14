#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from pathlib import Path
import socket
import signal
import sys
import threading
import traceback
import time

from enum import Enum, auto
from shared.Logger import Logger
from shared.ConfigLoader import ConfigLoader
from server.modules.protocol.PacketContext import PacketContext
from server.modules.protocol.packet_batch import (
    PacketBatch,
    send_packet_batch_under_lock,
)
from server.modules.protocol.ServerOutput import (
    project_name,
    log_raw_packet,
    should_log_packet,
)
from server.modules.interpretation.EncryptedWorldStream import EncryptedWorldStream
from server.modules.interpretation.OpcodeResolver import OpcodeResolver
from server.modules.interpretation.parser import parse_plain_packets
from server.modules.interpretation.utils import dsl_decode, build_world_header_plain
from server.modules.interpretation.utils import initialize_dsl_runtime
from server.modules.crypto.ARC4Crypto import Arc4CryptoHandler as WorldCryptoHandler
from server.session.world_session import WorldSession
from server.session.runtime import bind_world_session, clear_world_session
from server.modules.handlers.world.mount.mount_service import load_mount_spells
from server.modules.handlers.world.pet.pet_service import load_battle_pets
from server.modules.handlers.world.teleport.teleport_service import load_teleports
from server.modules.handlers.world.state.global_state import global_state
from server.modules.handlers.world.transport_runtime import (
    start_world_transport_manager,
    stop_world_transport_manager,
)
from server.modules.handlers.world.movements.manager import get_movement_manager
from server.modules.handlers.world.runtime.lifecycle import handle_disconnect_session
from server.modules.handlers.world.addons import load_from_db as load_addon_cache
from server.modules.api.bridge_worker import start_world_api_bridge, stop_world_api_bridge

try:
    from server.modules.handlers.WorldHandlers import (
        opcode_handlers,
        get_auth_challenge,
        reset_state as reset_handler_state,
        preload_cache as preload_handler_cache,
    )
except Exception:
    opcode_handlers = {}
    get_auth_challenge = None
    reset_handler_state = None
    preload_handler_cache = None






# ---- Configuration ------------------------------------------------------

config = ConfigLoader.load_config()

from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.handlers.world.feature_config import (
    log_effective_world_feature_config,
    taxi_movement_debug_enabled,
)
from server.modules.handlers.world.collision.geometry_shadow import log_geometry_shadow_initialization
from server.modules.opcodes.WorldOpcodes import (
    WORLD_CLIENT_OPCODES,
    WORLD_SERVER_OPCODES,
    lookup as world_lookup,
)
from server.modules.handlers.WorldHandlers import opcode_handlers, get_auth_challenge, reset_state, preload_cache, handle_disconnect


# ---- Opcodes ----
SERVER_OPCODE_BY_NAME = {
    name: code for code, name in WORLD_SERVER_OPCODES.items()
}

opcode_resolver = OpcodeResolver(
    WORLD_CLIENT_OPCODES,
    WORLD_SERVER_OPCODES,
    world_lookup,
)


# ---- Opcodes constants ----
try:
    AUTH_SESSION_OPCODE = world_lookup.WorldClientOpcodes.CMSG_AUTH_SESSION.value
except Exception:
    AUTH_SESSION_OPCODE = 0x00B2  # fallback


AUTH_RESPONSE_OPCODE = EncryptedWorldStream.AUTH_RESPONSE_OPCODE


# ---- Handlers ----
WORLD_HANDLERS = opcode_handlers


HOST = config["worldserver"]["host"]
PORT = config["worldserver"]["port"]
log_effective_world_feature_config()
log_geometry_shadow_initialization()
STARTED_AT = time.time()
running = True
restart_requested = False
_ACTIVE_CLIENTS_LOCK = threading.Lock()
_ACTIVE_CLIENTS: dict[int, tuple[socket.socket, object, tuple[str, int]]] = {}


HANDSHAKE_SERVER = b"0\x00WORLD OF WARCRAFT CONNECTION - SERVER TO CLIENT\x00"
HANDSHAKE_CLIENT = b"0\x00WORLD OF WARCRAFT CONNECTION - CLIENT TO SERVER\x00"


def _hex_or_dash(payload: bytes, *, limit: int = 96) -> str:
    raw = bytes(payload or b"")
    if not raw:
        return "-"
    compact = raw.hex()
    if len(compact) <= int(limit):
        return compact
    return f"{compact[:int(limit)]}..."


def _pet_battle_trace_active(session: object) -> bool:
    active_battle = getattr(session, "pet_battle_session", None)
    if active_battle is not None and bool(getattr(active_battle, "active", False)):
        return True
    until = float(getattr(session, "pet_battle_trace_until", 0.0) or 0.0)
    if until <= 0.0:
        return False
    if time.monotonic() > until:
        return False
    return True


def _pet_battle_trace_delta(session: object) -> float:
    started = float(getattr(session, "pet_battle_trace_started_at", 0.0) or 0.0)
    if started <= 0.0:
        return 0.0
    return max(0.0, float(time.monotonic()) - started)


def _log_opcode_trace(session: object, opcode: int, name: str, payload: bytes) -> None:
    Logger.info(
        "[OPCODE_TRACE] opcode=%s opcode_hex=0x%04X size=%s payload=%s",
        int(opcode),
        int(opcode) & 0xFFFF,
        len(payload or b""),
        _hex_or_dash(payload),
    )
    if not _pet_battle_trace_active(session):
        return
    active_battle = getattr(session, "pet_battle_session", None)
    battle_id = int(getattr(active_battle, "battle_id", 0) or 0)
    if battle_id <= 0:
        battle_id = int(getattr(session, "pet_battle_trace_battle_id", 0) or 0)
    active_flag = bool(getattr(active_battle, "active", False))
    if active_battle is None:
        active_flag = bool(getattr(session, "pet_battle_trace_active", False))
    Logger.info(
        "[PETBATTLE_TRACE] t_rel=%.3f ts=%.3f opcode=0x%04X name=%s size=%s payload=%s battle_id=%s active=%s",
        _pet_battle_trace_delta(session),
        time.monotonic(),
        int(opcode) & 0xFFFF,
        str(name),
        len(payload or b""),
        _hex_or_dash(payload),
        battle_id,
        int(active_flag),
    )

# ---- Signal handling ----------------------------------------------------

def sigint(sig, frame):
    """Gracefully stop worldserver on Ctrl+C."""
    global running, restart_requested
    signal_name = getattr(sig, "name", None) or str(int(sig))
    restart_requested = False
    Logger.info("[WorldServer] shutdown requested via %s", signal_name)
    running = False


def request_restart() -> None:
    """Request a clean worldserver restart from the main loop."""
    global running, restart_requested
    restart_requested = True
    running = False
    Logger.info("[WorldServer] restart requested")


def _shutdown_active_clients() -> None:
    with _ACTIVE_CLIENTS_LOCK:
        clients = list(_ACTIVE_CLIENTS.values())
        _ACTIVE_CLIENTS.clear()  # 🔥 viktigt

    if not clients:
        return

    Logger.info(f"[WorldServer] Closing {len(clients)} active world connection(s)")

    for sock, conn_session, addr in clients:
        try:
            handle_disconnect_session(conn_session)
        except Exception as exc:
            Logger.warning(f"[WorldServer] graceful disconnect failed for {addr}: {exc}")

        # 🔥 TA BORT FRÅN GLOBAL STATE
        try:
            state = getattr(conn_session, "global_state", None)
            if state and hasattr(state, "sessions"):
                state.sessions.discard(conn_session)
        except Exception as exc:
            Logger.warning(f"[WorldServer] session cleanup failed for {addr}: {exc}")

        conn_session.active = False

        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass

        try:
            sock.close()
        except Exception:
            pass


def _log_plants_vs_ghouls_loaded() -> None:
    from server.modules.handlers.world.features.plants_vs_ghouls import (
        get_plants_vs_ghouls_manager,
    )
    from server.modules.handlers.world.features.plants_vs_ghouls.definitions import (
        LANE_COUNT,
        PLANT_DEFINITIONS,
        WAVE_DEFINITIONS,
        ZOMBIE_DEFINITION,
    )

    _ = get_plants_vs_ghouls_manager()
    Logger.info(
        "[Plants vs Ghouls] Loaded prototype lanes=%s waves=%s plants=%s zombie_entry=%s",
        int(LANE_COUNT),
        len(WAVE_DEFINITIONS),
        len(PLANT_DEFINITIONS),
        int(ZOMBIE_DEFINITION.entry),
    )


def _log_halfhill_farming_loaded() -> None:
    from server.modules.handlers.world.features.halfhill_farming import (
        get_halfhill_farm_manager,
    )
    from server.modules.handlers.world.features.halfhill_farming.definitions import (
        CROPS_BY_SEED_ITEM,
        HALFHILL_MAP_ID,
        MANAGED_PLOT_GUIDS,
    )

    _ = get_halfhill_farm_manager()
    Logger.info(
        "[HalfhillFarm] Loaded prototype map=%s plots=%s crops=%s",
        int(HALFHILL_MAP_ID),
        len(MANAGED_PLOT_GUIDS),
        len(CROPS_BY_SEED_ITEM),
    )


def _log_pet_battles_loaded() -> None:
    from server.modules.handlers.world.features.pet_battles import (
        get_pet_battle_manager,
    )

    _ = get_pet_battle_manager()
    Logger.info(
        "[PetBattle] Loaded prototype mode=ui-only command=.petbattle start|stop",
    )


# ---- Utility helpers ----------------------------------------------------
"""def build_world_packet(opcode_name: str, payload: bytes) -> bytes:
    
    Build raw world packet: packed header (size<<13|opcode) + payload.
    Handles the auth-response size quirk if needed.
    
    opcode = SERVER_OPCODE_BY_NAME.get(opcode_name)
    if opcode is None:
        raise KeyError(f"Unknown server opcode: {opcode_name}")

    size = len(payload)
  #  if opcode == _AUTH_RESPONSE_OPCODE_INT:
    size += 4  # legacy quirk

    header = struct.pack("<I", (size << 13) | (opcode & 0x1FFF))
    return header + payload

def safe_decode(direction: str, name: str, raw_header: bytes, payload: bytes) -> None:
    Decode DSL packets via interpretation without crashing handlers.
    try:
        interpreter.interpret(name, raw_header, payload)
    except Exception as exc:
        Logger.error(f"[{direction}] decode failed for {name}: {exc}")
        Logger.error(traceback.format_exc())"""


"""def parse_client_packets(data, encrypted, stream, buffer, crypto):
    if not encrypted:
        # Plain header: <uint16 size><uint16 opcode>
        return parse_plain_packets(data, "C")

    buffer.extend(data)
    return stream.feed(buffer, crypto=crypto, direction="C")"""


def build_encrypted_response(packets, crypto) -> bytes:
    """Encrypt only the headers for server responses."""
    out = bytearray()

    for raw_header, h, payload in packets:
        if h.cmd < 0:
            out.extend(raw_header)
            out.extend(payload)
            continue

        size_field = len(payload)
        if h.cmd == AUTH_RESPONSE_OPCODE:
            size_field += 4

        packed = crypto.pack_data(h.cmd, size_field)
        if packed is None:
            Logger.error("[WorldServer] Failed to pack world header")
            continue

        enc_header = crypto.encrypt_send(packed)
        out.extend(enc_header)
        out.extend(payload)

    return bytes(out)


def parse_server_packets(raw: bytes):
    """
    Parse server packets that already contain packed world headers (size<<13 | opcode).
    Keeps payloads plaintext; used for logging/DSL decode before header encryption.
    """
    buf = bytearray(raw)
    packets = []

    while len(buf) >= 4:
        header = bytes(buf[:4])
        del buf[:4]

        hdr = WorldCryptoHandler().unpack_data(header)
        size = hdr.size
        cmd = hdr.cmd

        if len(buf) < size:
            break

        payload = bytes(buf[:size])
        del buf[:size]

        class Header:
            pass

        h = Header()
        h.size = size
        h.cmd = cmd
        h.hex = f"0x{cmd:04X}"
        h.header_raw = header

        packets.append((header, h, payload))

    return packets

def normalize_responses(response):
    if response is None:
        return []

    if isinstance(response, tuple):
        response = [response]

    normalized = []

    for item in response:
        if not isinstance(item, (tuple, list)):
            raise TypeError(f"Invalid response item: {item!r}")

        opcode = item[0]
        payload = item[1]
        is_raw = False

        # payload kan vara (bytes, True)
        if isinstance(payload, tuple):
            payload, is_raw = payload
            is_raw = bool(is_raw)
        elif len(item) >= 3:
            is_raw = bool(item[2])

        normalized.append((opcode, payload, is_raw))

    return normalized

# ---- Client session handler ---------------------------------------------

def _cleanup_dead_sessions():
    while running:
        now = time.time()

        with _ACTIVE_CLIENTS_LOCK:
            clients = list(_ACTIVE_CLIENTS.values())

        for sock, session, addr in clients:
            guid = int(getattr(session, "char_guid", 0) or 0)

            # --- skip non-player sessions ---
            if guid <= 0:
                continue

            last = float(getattr(session, "last_activity", 0) or 0)
            age = now - last

            # 60 sek timeout
            if age > 60:
                Logger.warning(
                    f"[TIMEOUT] killing dead player guid={guid} age={age:.1f}s addr={addr}"
                )

                try:
                    handle_disconnect_session(session)
                except Exception as exc:
                    Logger.warning(f"[TIMEOUT] disconnect failed: {exc}")

                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass

                try:
                    sock.close()
                except Exception:
                    pass

        time.sleep(5)


class WorldState(Enum):
    NEW = auto()
    HANDSHAKE_SENT = auto()
    AUTH_PLAIN = auto()
    WORLD_ENCRYPTED = auto()

def handle_client(sock: socket.socket, addr: tuple[str, int]) -> None:
    Logger.info(f"[WorldServer] New connection from {addr}")

    conn_session = WorldSession()
    bind_world_session(conn_session)
    conn_session.world_socket = sock
    conn_session.remote_addr = addr
    conn_session._disconnect_handled = False
    conn_session.last_activity = time.time()
    send_lock = threading.Lock()

    with _ACTIVE_CLIENTS_LOCK:
        _ACTIVE_CLIENTS[id(conn_session)] = (sock, conn_session, addr)

    if reset_handler_state:
        reset_handler_state()

    crypto = WorldCryptoHandler()
    stream = EncryptedWorldStream()
    buffer = bytearray()

    state = WorldState.NEW
    encrypted = False
    recv_calls = 0
    recv_calls_with_data = 0
    any_client_bytes_received = False

    def _taxi_xmap_debug(message: str, *args) -> None:
        if not taxi_movement_debug_enabled():
            return
        Logger.info(message, *args)

    def _send_normalized_responses(target_sock: socket.socket, responses) -> None:
        normalized = normalize_responses(responses)
        if not normalized:
            return

        def _log_discarded_transition_batch(batch: PacketBatch) -> None:
            try:
                from server.modules.handlers.world.transport_debug import (
                    TransportDebugEvent,
                    log_transport_event,
                )

                log_transport_event(
                    TransportDebugEvent.PACKET_BATCH_DISCARDED,
                    player_guid=int(getattr(conn_session, "char_guid", 0) or 0),
                    reason="transition_ownership_changed",
                    batch_generation=batch.transition_generation,
                    batch_owner=str(batch.transition_owner or "none"),
                    current_generation=int(
                        getattr(conn_session, "world_transition_generation", 0)
                        or 0
                    ),
                    current_owner=str(
                        getattr(conn_session, "world_transition_owner", "")
                        or "none"
                    ),
                    packets=len(normalized),
                )
            except Exception as exc:
                Logger.debug(
                    "[PacketBatch] discard diagnostic failed error=%s",
                    str(exc),
                )

        def _send_locked_batch() -> None:
            for item in normalized:
                if len(item) == 2:
                    opcode_name, payload = item
                    is_raw = False
                else:
                    opcode_name, payload, is_raw = item

                if opcode_name in {
                    "SMSG_TRANSFER_PENDING",
                    "SMSG_NEW_WORLD",
                    "SMSG_ON_MONSTER_MOVE",
                }:
                    taxi_state = getattr(conn_session, "taxi_state", None)
                    _taxi_xmap_debug(
                        "[TAXI_XMAP_DEBUG] send_packet opcode=%s player=%s map=%s "
                        "phase=%s pending=%s size=%s",
                        str(opcode_name),
                        int(getattr(conn_session, "char_guid", 0) or 0),
                        int(getattr(conn_session, "map_id", 0) or 0),
                        str(getattr(taxi_state, "phase", "")),
                        getattr(conn_session, "pending_taxi_transfer", None),
                        len(payload),
                    )

                if is_raw:
                    if should_log_packet("worldserver", opcode_name):
                        Logger.info(
                            f"[WorldServer] S→C {opcode_name} (RAW passthrough, size={len(payload)})"
                        )
                    log_raw_packet("worldserver", opcode_name, f"[WorldServer] S→C RAW {opcode_name}", payload)
                    target_sock.sendall(payload)
                    continue

                opcode_s = SERVER_OPCODE_BY_NAME[opcode_name]
                size = len(payload)

                if opcode_s == AUTH_RESPONSE_OPCODE:
                    size += 4

                if encrypted:
                    packed = crypto.pack_data(opcode_s, size)
                    header = crypto.encrypt_send(packed)
                else:
                    header = build_world_header_plain(opcode_s, payload)

                if should_log_packet("worldserver", opcode_name):
                    Logger.info(
                        f"[WorldServer] S→C {opcode_name} "
                        f"(0x{opcode_s:04X}) encrypted={encrypted} size={len(payload)}"
                    )
                log_raw_packet("worldserver", opcode_name, f"[WorldServer] S→C RAW {opcode_name}", header + payload)

                target_sock.sendall(header)
                target_sock.sendall(payload)

        send_packet_batch_under_lock(
            conn_session,
            responses,
            send_lock,
            _send_locked_batch,
            on_discard=_log_discarded_transition_batch,
        )

    conn_session.global_state = global_state
    conn_session.send_response = lambda responses: _send_normalized_responses(sock, responses)

    try:
        # ---- SERVER → CLIENT HANDSHAKE ----
        sock.sendall(HANDSHAKE_SERVER)
        Logger.success("[WorldServer] → client HANDSHAKE")
        log_raw_packet(
            "worldserver",
            "HANDSHAKE",
            "[WorldServer] S→C RAW HANDSHAKE",
            HANDSHAKE_SERVER,
        )
        state = WorldState.HANDSHAKE_SENT

        while running:
            try:
                data = sock.recv(4096)
                recv_calls += 1
            except ConnectionResetError as exc:
                Logger.error(
                    "[WorldServer] recv reset state=%s encrypted=%s addr=%s err=%s",
                    str(state.name if hasattr(state, "name") else state),
                    int(bool(encrypted)),
                    addr,
                    exc,
                )
                Logger.error(
                    "[WorldServer] recv reset diagnostics recv_calls=%s recv_calls_with_data=%s any_bytes_received=%s",
                    recv_calls,
                    recv_calls_with_data,
                    int(any_client_bytes_received),
                )
                if state == WorldState.HANDSHAKE_SENT:
                    Logger.error(
                        "[WorldServer] client reset before HANDSHAKE_WORLD_C addr=%s",
                        addr,
                    )
                raise
            if not data:
                Logger.info(
                    "[WorldServer] peer closed before sending any bytes state=%s encrypted=%s addr=%s recv_calls=%s",
                    str(state.name if hasattr(state, "name") else state),
                    int(bool(encrypted)),
                    addr,
                    recv_calls,
                )
                Logger.info(f"[WorldServer] {addr}: disconnected")
                break

            recv_calls_with_data += 1
            any_client_bytes_received = True
            Logger.info(
                "[WorldServer] recv bytes=%s state=%s encrypted=%s addr=%s",
                len(data),
                str(state.name if hasattr(state, "name") else state),
                int(bool(encrypted)),
                addr,
            )
            Logger.info("[WorldServer] recv raw hex=%s", data.hex())
            Logger.info("[WorldServer] recv raw repr=%r", data)

            if state == WorldState.HANDSHAKE_SENT:
                log_raw_packet(
                    "worldserver",
                    "HANDSHAKE",
                    "[WorldServer] C→S RAW PRE_AUTH",
                    data,
                )

            IGNORE_ACTIVITY_OPCODES = {
                "CMSG_WORLD_STATE_UI_TIMER_UPDATE",
                "CMSG_PING",
                "CMSG_TIME_SYNC_RESP",
            }


        

            # ---- PARSE BY ENCRYPTION STATE ----
            if not encrypted:
                Logger.info(
                    "[WorldServer] before parse_plain_packets state=%s recv_len=%s addr=%s",
                    str(state.name if hasattr(state, "name") else state),
                    len(data),
                    addr,
                )
                packets = parse_plain_packets(data, "C")
            else:
                buffer.extend(data)
                packets = stream.feed(buffer, crypto=crypto, direction="C")

            for raw_header, h, payload in packets:
                opcode = h.cmd

                # ---- CLIENT HANDSHAKE ----
                if state == WorldState.HANDSHAKE_SENT and opcode < 0:
                    Logger.info("[WorldServer] ← client HANDSHAKE")

                    challenge = get_auth_challenge()
                    responses = normalize_responses(challenge)
                    out = bytearray()

                    for item in responses:
                        if len(item) == 2:
                            opcode_name, payload = item
                            is_raw = False
                        else:
                            opcode_name, payload, is_raw = item

                        if is_raw:
                            Logger.info(
                                f"[WorldServer] S→C {opcode_name} (RAW passthrough, size={len(payload)})"
                            )
                            out.extend(payload)
                            continue

                        opcode_s = SERVER_OPCODE_BY_NAME[opcode_name]
                        header = build_world_header_plain(opcode_s, payload)

                        Logger.info(
                            f"[WorldServer] S→C {opcode_name} (0x{opcode_s:04X}) "
                            f"encrypted=False size={len(payload)}"
                        )

                        out.extend(header)
                        out.extend(payload)

                    sock.sendall(out)
                    Logger.success("[WorldServer] → client SMSG_AUTH_CHALLENGE")
                    state = WorldState.AUTH_PLAIN
                    continue

                # ---- NORMAL CLIENT PACKET ----
                name = opcode_resolver.decode_opcode(opcode, "C")
                _log_opcode_trace(conn_session, opcode, name, payload)
                
                ALIVE_OPCODES = {
                    "CMSG_PING",
                    "CMSG_TIME_SYNC_RESP",
                    "CMSG_WORLD_STATE_UI_TIMER_UPDATE",
                }

                if name in ALIVE_OPCODES:
                    conn_session.last_activity = time.time()

                if should_log_packet("worldserver", name):
                    Logger.info(f"[WorldServer] C→S {name}")
                log_raw_packet("worldserver", name, f"[WorldServer] C→S RAW {name}", raw_header + payload)

                # ---- DETECT AUTH_SESSION (BUT DO NOT HANDLE IT) ----
                auth_session_seen = (
                    state == WorldState.AUTH_PLAIN
                    and opcode == AUTH_SESSION_OPCODE
                )

                # ---- ROUTE TO WORLD HANDLERS ----
                handler = opcode_handlers.get(name)
                if not handler:
                    continue

                decoded = dsl_decode(name, payload, silent=True) or {}
                ctx = PacketContext(
                    sock=sock,
                    direction="C",
                    opcode=opcode,
                    name=name,
                    payload=payload,
                    decoded=decoded,
                    session=conn_session,
                    account_id=getattr(conn_session, "account_id", None),
                    realm_id=getattr(conn_session, "realm_id", None),
                )

                loading_trace_started = time.monotonic()
                if name == "CMSG_LOADING_SCREEN_NOTIFY":
                    conn_session.loading_screen_trace_id = (
                        f"{int(getattr(conn_session, 'char_guid', 0) or 0)}-"
                        f"{int(loading_trace_started * 1000.0)}"
                    )
                    Logger.info(
                        "[LoadingScreenTrace] trace_id=%s stage=network_handler "
                        "event=entering",
                        str(
                            getattr(conn_session, "loading_screen_trace_id", "pending")
                            or "pending"
                        ),
                    )
                try:
                    err, response = handler(ctx)
                except Exception as exc:
                    if name == "CMSG_LOADING_SCREEN_NOTIFY":
                        Logger.info(
                            "[LoadingScreenTrace] trace_id=%s stage=network_handler "
                            "event=exception elapsed_ms=%.3f error=%s",
                            str(
                                getattr(conn_session, "loading_screen_trace_id", "unknown")
                                or "unknown"
                            ),
                            (time.monotonic() - loading_trace_started) * 1000.0,
                            str(exc),
                        )
                    raise
                if name == "CMSG_LOADING_SCREEN_NOTIFY":
                    response_count = (
                        len(response)
                        if isinstance(response, list)
                        else (1 if response else 0)
                    )
                    Logger.info(
                        "[LoadingScreenTrace] trace_id=%s stage=network_handler "
                        "event=leaving elapsed_ms=%.3f err=%s packets=%s empty=%s",
                        str(
                            getattr(conn_session, "loading_screen_trace_id", "unknown")
                            or "unknown"
                        ),
                        (time.monotonic() - loading_trace_started) * 1000.0,
                        int(err or 0),
                        response_count,
                        "true" if not response else "false",
                    )
                if err or not response:
                    if name == "CMSG_LOADING_SCREEN_NOTIFY":
                        Logger.info(
                            "[LoadingScreenTrace] trace_id=%s stage=network_send "
                            "event=early_return reason=%s packets=0",
                            str(
                                getattr(conn_session, "loading_screen_trace_id", "unknown")
                                or "unknown"
                            ),
                            "handler_error" if err else "empty_response",
                        )
                    continue

                # ---- INIT ARC4 AFTER HANDLER RAN ----
                if auth_session_seen:
                    try:
                        account = (
                            decoded.get("account")
                            or decoded.get("username")
                            or decoded.get("I")
                        )

                        acc = DatabaseConnection.get_user_by_username(account.upper())
                        crypto.init_arc4(acc.session_key.hex())

                        encrypted = True
                        state = WorldState.WORLD_ENCRYPTED

                        Logger.success(f"[WorldServer] ARC4 initialized for {account}")
                    except Exception as exc:
                        Logger.error("[WorldServer] Failed to init ARC4")
                        Logger.error(exc)
                        return

                # ---- SEND SERVER RESPONSES ----
                if name == "CMSG_LOADING_SCREEN_NOTIFY":
                    Logger.info(
                        "[LoadingScreenTrace] trace_id=%s stage=network_send "
                        "event=entering packets=%s",
                        str(
                            getattr(conn_session, "loading_screen_trace_id", "unknown")
                            or "unknown"
                        ),
                        len(response) if isinstance(response, list) else 1,
                    )
                send_started = time.monotonic()
                try:
                    _send_normalized_responses(sock, response)
                except Exception as exc:
                    if name == "CMSG_LOADING_SCREEN_NOTIFY":
                        Logger.info(
                            "[LoadingScreenTrace] trace_id=%s stage=network_send "
                            "event=exception elapsed_ms=%.3f error=%s",
                            str(
                                getattr(conn_session, "loading_screen_trace_id", "unknown")
                                or "unknown"
                            ),
                            (time.monotonic() - send_started) * 1000.0,
                            str(exc),
                        )
                    raise
                if name == "CMSG_LOADING_SCREEN_NOTIFY":
                    Logger.info(
                        "[LoadingScreenTrace] trace_id=%s stage=network_send "
                        "event=leaving elapsed_ms=%.3f",
                        str(
                            getattr(conn_session, "loading_screen_trace_id", "unknown")
                            or "unknown"
                        ),
                        (time.monotonic() - send_started) * 1000.0,
                    )
                    try:
                        from server.modules.handlers.world.opcodes import (
                            movement as movement_handlers,
                        )

                        post_bootstrap_responses = (
                            movement_handlers.complete_queued_post_bootstrap_transport_reattach(
                                conn_session
                            )
                        )
                    except Exception as exc:
                        Logger.warning(
                            "[TransportTransfer] post_bootstrap_reattach_failed "
                            "reason=post_send_exception error=%s",
                            str(exc),
                        )
                        post_bootstrap_responses = []
                    if post_bootstrap_responses:
                        try:
                            _send_normalized_responses(sock, post_bootstrap_responses)
                        except Exception as exc:
                            Logger.warning(
                                "[TransportTransfer] post_bootstrap_reattach_failed "
                                "reason=separate_update_send error=%s",
                                str(exc),
                            )

    except Exception as exc:
        Logger.error(f"[WorldServer] error: {exc}")
        Logger.error(traceback.format_exc())
    finally:
        with _ACTIVE_CLIENTS_LOCK:
            _ACTIVE_CLIENTS.pop(id(conn_session), None)

        # 🔥 TA BORT SESSION FRÅN GLOBAL STATE (DETTA ÄR DIN BUG)
        try:
            state = getattr(conn_session, "global_state", None)
            if state and hasattr(state, "sessions"):
                state.sessions.discard(conn_session)
        except Exception as exc:
            Logger.warning(f"[WorldServer] session cleanup failed: {exc}")

        # markera session som död (bra för safety)
        conn_session.active = False

        try:
            handle_disconnect_session(conn_session)
        except Exception as exc:
            Logger.warning(f"[WorldServer] disconnect handler failed: {exc}")

        clear_world_session()

        try:
            sock.close()
        except Exception:
            pass

        Logger.info(f"[WorldServer] Closed connection from {addr}")

# ---- Server loop --------------------------------------------------------

def run_world() -> None:
    global running, restart_requested
    running = True
    restart_requested = False

    Logger.configure(scope="worldserver", reset=True)
    signal.signal(signal.SIGINT, sigint)
    signal.signal(signal.SIGTERM, sigint)

    Logger.info(f"{project_name()} WorldServer")
    loaded, total = initialize_dsl_runtime(watch=True)
    pct = int((loaded * 100 / total)) if total else 0
    Logger.info(f"DSL runtime ready [{loaded}/{total}] {pct}%")
    DatabaseConnection.initialize()
    DatabaseConnection.preload_world_cache()
    try:
        load_addon_cache()
    except Exception as exc:
        Logger.warning(f"[ADDONS] preload failed: {exc}")
    try:
        load_mount_spells(DatabaseConnection.world())
    except Exception as exc:
        Logger.warning(f"[Mount] preload failed: {exc}")
    try:
        load_battle_pets(DatabaseConnection.world())
    except Exception as exc:
        Logger.warning(f"[BattlePet] preload failed: {exc}")
    try:
        load_teleports(DatabaseConnection.world())
    except Exception as exc:
        Logger.warning(f"[Teleport] preload failed: {exc}")
    try:
        _log_plants_vs_ghouls_loaded()
    except Exception as exc:
        Logger.warning(f"[PvG] preload failed: {exc}")
    try:
        _log_halfhill_farming_loaded()
    except Exception as exc:
        Logger.warning(f"[HalfhillFarm] preload failed: {exc}")
    try:
        _log_pet_battles_loaded()
    except Exception as exc:
        Logger.warning(f"[PetBattle] preload failed: {exc}")
    try:
        start_world_api_bridge()
    except Exception as exc:
        Logger.warning(f"[ChatAPI] bridge startup failed: {exc}")
    try:
        preload_cache()
    except Exception:
        pass
    try:
        get_movement_manager().load_templates()
    except Exception as exc:
        Logger.warning(f"[MovementManager] template load failed: {exc}")
    try:
        start_world_transport_manager()
    except Exception as exc:
        Logger.warning(f"[TransportManager] startup failed: {exc}")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(5)

    Logger.success(f"WorldServer listening on {HOST}:{PORT}")
    threading.Thread(target=_cleanup_dead_sessions, daemon=True).start()

    while running:
        try:
            srv.settimeout(1.0)
            sock, addr = srv.accept()
            threading.Thread(target=handle_client, args=(sock, addr), daemon=True).start()
        except socket.timeout:
            continue
        except Exception as exc:
            Logger.error(f"[WorldServer] Server error: {exc}")
            Logger.error(traceback.format_exc())

    Logger.info("WorldServer stopping…")
    try:
        stop_world_api_bridge()
    except Exception as exc:
        Logger.warning(f"[ChatAPI] bridge shutdown failed: {exc}")
    _shutdown_active_clients()
    try:
        stop_world_transport_manager()
    except Exception as exc:
        Logger.warning(f"[TransportManager] shutdown failed: {exc}")
    srv.close()

    if restart_requested:
        launcher = Path(__file__).resolve().parents[1] / "worldserver.py"
        Logger.info("[WorldServer] restarting via %s", str(launcher))
        os.execv(sys.executable, [sys.executable, str(launcher)])




# ---- Main entry ---------------------------------------------------------





if __name__ == "__main__":
    run_world()
