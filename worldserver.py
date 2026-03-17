#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import signal
import threading
import traceback

from enum import Enum, auto
from shared.Logger import Logger
from shared.ConfigLoader import ConfigLoader
# from utils.ProtocolBootstrap import load_bootstrap
from server.modules.interpretation.EncryptedWorldStream import EncryptedWorldStream
from server.modules.interpretation.OpcodeResolver import OpcodeResolver
from server.modules.interpretation.PacketInterpreter import (
    DumpPolicy,
    DslDecoder,
    JsonNormalizer,
    PacketDumper,
    PacketInterpreter,
)
from server.modules.interpretation.parser import parse_plain_packets
from server.modules.interpretation.utils import dsl_decode, build_world_header_plain


# ---- Configuration ------------------------------------------------------

config = ConfigLoader.load_config()
config["Logging"]["logging_levels"] = "Information, Success, Error"

program = config["program"]
expansion = config.get("expansion")
version = config["version"]

from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.opcodes.WorldOpcodes import (
    WORLD_CLIENT_OPCODES,
    WORLD_SERVER_OPCODES,
    lookup as world_lookup,
)
from server.modules.handlers.WorldHandlers import opcode_handlers, get_auth_challenge, reset_state, preload_cache
from server.modules.PacketDump import PacketDump


# ---- Database ----
DatabaseConnection.initialize()
DatabaseConnection.preload_world_cache()


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


# ---- Optional handler hooks ----
# (matchar bootstrap-strukturen)
# sätt None om de inte finns i din fil
try:
    preload_cache()
except Exception:
    pass


# bootstrap = load_bootstrap()
# DatabaseConnection = bootstrap.load_database()
# DatabaseConnection.initialize()
# DatabaseConnection.preload_world_cache()
# PacketDump = bootstrap.get_packet_dump()

HOST = config["worldserver"]["host"]
PORT = config["worldserver"]["port"]
running = True


# ---- Opcodes/handlers ---------------------------------------------------

# WORLD_CLIENT_OPCODES, WORLD_SERVER_OPCODES, world_lookup = bootstrap.load_world_opcodes()
# SERVER_OPCODE_BY_NAME = {name: code for code, name in WORLD_SERVER_OPCODES.items()}

# opcode_resolver = OpcodeResolver(WORLD_CLIENT_OPCODES, WORLD_SERVER_OPCODES, world_lookup)

# try:
    # AUTH_SESSION_OPCODE = world_lookup.WorldClientOpcodes.CMSG_AUTH_SESSION.value
#except Exception:
   # AUTH_SESSION_OPCODE = 0x00B2  # MoP fallback

# AUTH_RESPONSE_OPCODE = EncryptedWorldStream.AUTH_RESPONSE_OPCODE

# handlers = bootstrap.load_world_handlers()
from server.modules.handlers.WorldHandlers import opcode_handlers

# try:
 #   handlers = bootstrap.load_world_handlers()
  #  opcode_handlers = handlers.get("opcode_handlers", {})
   # get_auth_challenge = handlers.get("get_auth_challenge")
 #   reset_handler_state = handlers.get("reset_state")
 #   preload_handler_cache = handlers.get("preload_cache")
 #   Logger.info("[WorldServer] Loaded world opcode handlers")

  #  Logger.info(f"get_auth_challenge={get_auth_challenge}")
  #  Logger.info(f"callable={callable(get_auth_challenge)}")
#except Exception:
 #   opcode_handlers = {}
  #  get_auth_challenge = None
   # reset_handler_state = None
 #   preload_handler_cache = None
  #  Logger.info("[WorldServer] No WorldHandlers found, raw fallback only")

#if preload_handler_cache:
 #   try:
  #      preload_handler_cache()
   # except Exception as exc:
    #    Logger.warning(f"[WorldServer] Handler cache preload failed: {exc}")


# ---- Interpretation helpers --------------------------------------------

packet_dumper = PacketDump(f"protocols/{program}/{expansion}/{version}/data")
interpreter = PacketInterpreter(
    decoder=DslDecoder(),
    normalizer=JsonNormalizer(),
    policy=DumpPolicy(dump=False, update=False),
    dumper=PacketDumper(packet_dumper),
)


# ---- Constants ----------------------------------------------------------

# HANDSHAKE_SERVER, HANDSHAKE_CLIENT = bootstrap.get_world_handshake()
# WorldCryptoHandler = bootstrap.get_world_crypto()

HANDSHAKE_SERVER = b"0\x00WORLD OF WARCRAFT CONNECTION - SERVER TO CLIENT\x00"
HANDSHAKE_CLIENT = b"0\x00WORLD OF WARCRAFT CONNECTION - CLIENT TO SERVER\x00"

# ---- Signal handling ----------------------------------------------------

def sigint(sig, frame):
    """Gracefully stop worldserver on Ctrl+C."""
    global running
    Logger.info("Shutting down WorldServer (Ctrl+C)…")
    running = False


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

class WorldState(Enum):
    NEW = auto()
    HANDSHAKE_SENT = auto()
    AUTH_PLAIN = auto()
    WORLD_ENCRYPTED = auto()

def handle_client(sock: socket.socket, addr: tuple[str, int]) -> None:
    Logger.info(f"[WorldServer] New connection from {addr}")

    if reset_handler_state:
        reset_handler_state()

    crypto = WorldCryptoHandler()
    stream = EncryptedWorldStream()
    buffer = bytearray()

    state = WorldState.NEW
    encrypted = False

    try:
        # ---- SERVER → CLIENT HANDSHAKE ----
        sock.sendall(HANDSHAKE_SERVER)
        Logger.success("[WorldServer] → client HANDSHAKE")
        state = WorldState.HANDSHAKE_SENT

        while running:
            data = sock.recv(4096)
            if not data:
                Logger.info(f"[WorldServer] {addr}: disconnected")
                break

            # ---- PARSE BY ENCRYPTION STATE ----
            if not encrypted:
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
                Logger.info(f"[WorldServer] C→S {name}")

                # ---- DETECT AUTH_SESSION (BUT DO NOT HANDLE IT) ----
                auth_session_seen = (
                    state == WorldState.AUTH_PLAIN
                    and opcode == AUTH_SESSION_OPCODE
                )

                # ---- ROUTE TO WORLD HANDLERS ----
                handler = opcode_handlers.get(name)
                if not handler:
                    continue

                err, response = handler(sock, opcode, payload)
                if err or not response:
                    continue

                # ---- INIT ARC4 AFTER HANDLER RAN ----
                if auth_session_seen:
                    try:
                        decoded = dsl_decode("CMSG_AUTH_SESSION", payload, silent=True)
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
                responses = normalize_responses(response)

                for item in responses:
                    # Backward compatible unpack
                    if len(item) == 2:
                        opcode_name, payload = item
                        is_raw = False
                    else:
                        opcode_name, payload, is_raw = item

                    if is_raw:
                        Logger.info(
                            f"[WorldServer] S→C {opcode_name} (RAW passthrough, size={len(payload)})"
                        )
                        sock.sendall(payload)
                        continue

                    # ---- Normal (non-RAW) packet path ----
                    opcode_s = SERVER_OPCODE_BY_NAME[opcode_name]
                    size = len(payload)

                    if opcode_s == AUTH_RESPONSE_OPCODE:
                        size += 4  # MoP quirk

                    if encrypted:
                        packed = crypto.pack_data(opcode_s, size)
                        header = crypto.encrypt_send(packed)
                    else:
                        header = build_world_header_plain(opcode_s, payload)

                    Logger.info(
                        f"[WorldServer] S→C {opcode_name} "
                        f"(0x{opcode_s:04X}) encrypted={encrypted} size={len(payload)}"
                    )

                    sock.sendall(header)
                    sock.sendall(payload)

    except Exception as exc:
        Logger.error(f"[WorldServer] error: {exc}")
        Logger.error(traceback.format_exc())
    finally:
        sock.close()
        Logger.info(f"[WorldServer] Closed connection from {addr}")

# ---- Server loop --------------------------------------------------------

def run_world() -> None:
    signal.signal(signal.SIGINT, sigint)

    Logger.info(
        f"{config['friendly_name']} "
        f"({config['program']}:{config.get('expansion')}:{config['version']}) WorldServer (Minimal Mode)"
    )

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(5)

    Logger.info(f"[WorldServer] Listening on {HOST}:{PORT}")

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
    srv.close()


# ---- Main entry ---------------------------------------------------------





if __name__ == "__main__":
    run_world()
