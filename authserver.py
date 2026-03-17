#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import signal
import traceback
import threading

from DSL.modules.dsl.DslRuntime import DslRuntime
from shared.Logger import Logger
from shared.ConfigLoader import ConfigLoader

from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.handlers.AuthHandlers import opcode_handlers as AUTH_HANDLERS
from server.modules.opcodes.AuthOpcodes import AUTH_CLIENT_OPCODES, AUTH_SERVER_OPCODES


config = ConfigLoader.load_config()
config["Logging"]["logging_levels"] = "Information, Success, Error"

DatabaseConnection.initialize()

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

def safe_decode(direction: str, name: str, payload: bytes):
    """Decode DSL packets without crashing handler logic."""
    if runtime is None:
        return

    try:
        runtime.decode(name, payload, silent=True)
    except Exception as exc:
        Logger.error(f"{direction}: decode failed for {name}: {exc}")
        Logger.error(traceback.format_exc())


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

            Logger.info("Direction: Client --> Server")
            Logger.info(f"Raw: {data.hex().upper()}")

            if opcode_name is None:
                Logger.warning(f"{addr}: Unknown opcode 0x{opcode:02X}")
                break

            safe_decode("Client", opcode_name, data)

            handler = AUTH_HANDLERS.get(opcode_name)
            if handler is None:
                Logger.warning(f"{addr}: No handler for {opcode_name}")
                break

            try:
                err, response = handler(sock, opcode, data)
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

            Logger.info("Direction: Client <-- Server")
            Logger.info(f"Raw: {response.hex().upper()}")

            if server_name:
                safe_decode("Server", server_name, response)

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

    signal.signal(signal.SIGINT, sigint)
    signal.signal(signal.SIGTERM, sigint)

    try:
        runtime = DslRuntime(
            config["program"],
            config["version"],
            watch=False,
            expansion=config.get("expansion"),
        )
        runtime.load_runtime_all()
        Logger.info("[AuthServer] DSL runtime ready (runtime mode, no JSON)")
    except Exception as exc:
        Logger.error(f"[AuthServer] Runtime init failed: {exc}")
        Logger.error(traceback.format_exc())
        raise

    Logger.info(
        f"{config['friendly_name']} "
        f"({config['program']}:{config.get('expansion')}:{config['version']}) "
        f"AuthServer (Minimal Mode)"
    )

    start_server()


if __name__ == "__main__":
    run_auth()