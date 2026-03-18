#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import signal
import traceback
import threading

from DSL.modules.DslRuntime import DslRuntime
from shared.Logger import Logger
from shared.ConfigLoader import ConfigLoader
from server.modules.PacketContext import PacketContext
from server.modules.ServerOutput import (
    dsl_warnings_enabled,
    project_name,
    log_decoded_packet,
    log_raw_packet,
    should_log_packet,
)

from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.handlers.AuthHandlers import (
    opcode_handlers as AUTH_HANDLERS,
    set_srp6_mode,
)
from server.modules.opcodes.AuthOpcodes import AUTH_CLIENT_OPCODES, AUTH_SERVER_OPCODES


config = ConfigLoader.load_config()

HOST = config["authserver"]["host"]
PORT = config["authserver"]["port"]
running = True
runtime = None


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
    """Handle a single authentication client connection."""
    Logger.info(f"New connection from {addr}")

    try:
        while True:
            data = sock.recv(1024)
            if not data:
                Logger.info(f"{addr}: disconnected")
                break

            opcode = data[0]
            opcode_name = AUTH_CLIENT_OPCODES.get(opcode)

            if opcode_name is None:
                Logger.warning(f"{addr}: Unknown opcode 0x{opcode:02X}")
                break

            if should_log_packet("authserver", opcode_name):
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
                )
                err, response = handler(ctx)
            except Exception as exc:
                Logger.error(f"{addr}: Handler crash: {exc}")
                Logger.error(traceback.format_exc())
                break

            if err != 0:
                Logger.warning(f"{addr}: Handler returned error={err}")
                break

            if not response:
                Logger.info(f"{addr}: Handler returned no response")
                continue

            server_op = response[0]
            server_name = AUTH_SERVER_OPCODES.get(server_op)

            if server_name:
                if should_log_packet("authserver", server_name):
                    Logger.info(f"[AuthServer] S→C {server_name}")
                log_raw_packet("authserver", server_name, "Raw", response)
                log_decoded_packet(
                    "authserver",
                    server_name,
                    safe_decode("Server", server_name, response),
                    label=server_name,
                )

            try:
                sock.send(response)
            except Exception as exc:
                Logger.error(f"{addr}: Failed to send response: {exc}")
                break

    except Exception as exc:
        Logger.error(f"{addr}: Unexpected error: {exc}")
        Logger.error(traceback.format_exc())

    finally:
        Logger.info(f"Closing connection from {addr}")
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
    global runtime

    Logger.configure(scope="dsl", reset=True)
    Logger.configure(scope="authserver", reset=True)
    signal.signal(signal.SIGINT, sigint)
    signal.signal(signal.SIGTERM, sigint)
    Logger.info(f"{project_name()} AuthServer")
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
