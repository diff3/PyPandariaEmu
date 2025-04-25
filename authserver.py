#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import signal
import sys
import threading
import traceback

from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger
from utils.BaseServerTemplates import BaseServer
from protocol.opcodes.AuthOpcodes import AuthOpcodes, AuthCode
from handlers.AuthHandler import opcode_handlers

config = ConfigLoader.load_config()

class AuthServer(BaseServer):
    """
    Authentication server that processes login requests.
    """

    def handle_client(self, client_socket):
        """
        Processes incoming authentication requests.
        """
        try:
            while not self.stop_event.is_set():
                data = client_socket.recv(1024)

                if not data:
                    break

                opcode = AuthOpcodes.getCodeName(AuthCode, data[0])
                print(data[0])
                print(opcode)
                handler = opcode_handlers.get(opcode)

                if handler:
                    Logger.info(f"{client_socket.getpeername()[0]}: {opcode}")
                    Logger.info(f"Data received: {data}")

                    error, response = handler(data)
                    
                    if error == 0:
                        client_socket.send(response)
                    else:
                        Logger.warning(f"Error {error}: Closing connection from {client_socket.getpeername()}")
                        break
                else:
                    Logger.warning(f"Unknown opcode: {opcode}")
                    break

        except Exception as e:
            error_details = traceback.format_exc()
            Logger.error(f"Error in AuthServer: {e}\n{error_details}")

        finally:
            Logger.info(f"Closing connection from {client_socket.getpeername()}")
            client_socket.close()


if __name__ == "__main__":
    stop_event = threading.Event()

    def handle_sigint(signal, frame):
        """Gracefully shuts down the AuthServer on Ctrl+C."""
        Logger.info("Shutting down AuthServer...")
        stop_event.set()

    signal.signal(signal.SIGINT, handle_sigint)

    Logger.info("Mist of Pandaria 5.4.8 AuthServer")

    auth_server = AuthServer(
        local_host=config['authserver']['host'],
        local_port=config['authserver']['port'],
        stop_event=stop_event
    )

    auth_thread = threading.Thread(target=auth_server.start_server, daemon=True)
    auth_thread.start()

    try:
        auth_thread.join()
    except KeyboardInterrupt:
        Logger.info("Exiting...")
        sys.exit(0)
