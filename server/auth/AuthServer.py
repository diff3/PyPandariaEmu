#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from server.auth.AuthHandler import Handler
from utils.Logger import Logger
from utils.auth.opcodes import *
import socket
import threading


class AuthServer:

    @staticmethod
    def client_handler(client_socket):

        try:
            while True:
                data = client_socket.recv(1024)

                if not data: break

                opcode = opcodes.getCodeName(AuthCode, data[0])
                handler = opcode_handlers.get(opcode, client_socket)

                if handler:
                    error, response = handler(data)
                else:
                    Logger.warning(f'Opcode: {opcode} is unknown') 

                if error:
                    Logger.warning(f"Closed connection from {client_socket.getpeername()}")
                    client_socket.close()

                client_socket.send(response)
        
        except:
            # Logger.warning(f'Unknown handler error')
            pass
        
        finally:
            Logger.success(f"Closed connection from {client_socket.getpeername()}")
            client_socket.close()

    @staticmethod
    def start(host, port):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(5)
        Logger.info(f'Listening at {host}:{port}')

        while True:
            client_socket, addr = server.accept()
            Logger.success(f'Accepted connection from {addr}')
            client_handler = threading.Thread(target=AuthServer.client_handler, args=(client_socket,))
            client_handler.start()


opcode_handlers = {
    "AUTH_LOGON_CHALLENGE": Handler.AuthLogonChallenge,
    "AUTH_LOGON_PROOF": Handler.AuthLogonProof,
    "REALM_LIST": Handler.RealmList,
    "AUTH_RECONNECT_CHALLENGE": Handler.AuthReconnectChallange,
    "AUTH_RECONNECT_PROOF": Handler.AuthReconnectProof
}