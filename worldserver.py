#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import signal
import sys
import threading
import traceback

from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger
from utils.BaseServerTemplates import BaseServer
from database.DatabaseConnection import DatabaseConnection
from protocol.opcodes.WorldOpcodes import WorldOpcodes

config = ConfigLoader.load_config()

class WorldServer(BaseServer):
    """
    Handles the World Server, processes client connections,
    and manages authentication and encryption setup.
    """

    def handle_client(self, client_socket):
        """
        Handles communication with a connected client.
        """
        try:
            client_socket.send(b'0\x00WORLD OF WARCRAFT CONNECTION - SERVER TO CLIENT\x00')

            while not self.stop_event.is_set():
                data = client_socket.recv(4096)
                if not data:
                    break

                header_raw = data[:4]
                cmd = int(header_raw[2:4][::-1].hex(), 16)
                opcode_name = WorldOpcodes.getClientOpCodeName(cmd)

                Logger.info(f"Received opcode: {opcode_name}")

                if data == b'0\x00WORLD OF WARCRAFT CONNECTION - CLIENT TO SERVER\x00':
                    self.send_auth_challenge(client_socket)

                elif opcode_name == "CMSG_AUTH_SESSION":
                    self.handle_auth_session(client_socket, data)

        except Exception as e:
            Logger.warning(f"Error handling client: {e}")
        finally:
            Logger.success(f"Closed connection from {client_socket.getpeername()}")
            client_socket.close()

    def send_auth_challenge(self, client_socket):
        """
        Sends an authentication challenge to the client.
        """
        payload = b'\x00' * 34 + b'\x01\xde\x88\xbe\x0c'
        header = "29004909"
        package = bytes.fromhex(header) + payload
        client_socket.send(package)
        Logger.info("Sent SMSG_AUTH_CHALLENGE")

    def handle_auth_session(self, client_socket, data):
        """
        Handles authentication session from client.
        """
        username = "DummyUser"  # Replace with actual parsing logic
        session_key = DatabaseConnection.get_mirrored_sessionkey_by_username(username=username)

        Logger.info(f"Initializing encryption for user: {username}")

        payload = b'\x80\x00\x04,*\x00\x00,\x00\x00\x00\x00\x00<\x01\x00\x00\x00Skyfire MoP\x00'
        header = b'\x00\x00'  # Placeholder for actual encryption logic
        package = header + payload
        client_socket.send(package)

        Logger.info("Sent SMSG_AUTH_RESPONSE")


if __name__ == "__main__":
    stop_event = threading.Event()

    def handle_sigint(signal, frame):
        """Gracefully shuts down the WorldServer on Ctrl+C."""
        Logger.info("Shutting down WorldServer...")
        stop_event.set()

    signal.signal(signal.SIGINT, handle_sigint)

    Logger.info("Mist of Pandaria 5.4.8 WorldServer")

    world_server = WorldServer(
        local_host=config['worldserver']['host'],
        local_port=config['worldserver']['port'],
        stop_event=stop_event
    )

    world_thread = threading.Thread(target=world_server.start_server, daemon=True)
    world_thread.start()

    try:
        while not stop_event.is_set():
            world_thread.join(timeout=1)
    except KeyboardInterrupt:
        Logger.info("Exiting WorldServer...")
        stop_event.set()
        sys.exit(0)
