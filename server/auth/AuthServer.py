#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-

import socket
import threading
import yaml
from server.auth.Decoder import AuthLogonChallengeC, AuthLogonProofC
from server.auth.Encoder import AuthProofData
from utils.Logger import Logger
from utils.opcodes import *


with open("etc/config.yaml", 'r') as file:
    config = yaml.safe_load(file)


class AuthServer:    

    @staticmethod
    def handle_client(client_socket, config):
        global_b = None
        global_B = None

        try:
            while True:
                data = client_socket.recv(1024)
                
                if not data:
                    break

                opcode = opcodes.getCode(data[0])

                if opcode == "AUTH_LOGON_CHALLENGE":
                    Logger.info(f'Received AUTH_LOGON_CHALLENGE')

                    decoded_data = AuthLogonChallengeC.unpack(data)
                    Logger.debug(f'{decoded_data}')
    
                    Logger.info(f'Sending AUTH_LOGON_CHALLENGE to client')
                    response, global_b, global_B = AuthProofData.create_auth_proof(decoded_data)
                    Logger.debug(f'{response}')

                    client_socket.send(response)
                elif opcode == "AUTH_LOGON_PROOF": 
                    Logger.info(f'Received AUTH_LOGON_PROOF')

                    decoded_data = AuthLogonProofC.unpack(data)
                    Logger.debug(f'{decoded_data}')

                    Logger.info(f'Sending AUTH_LOGON_PROOF to client')
                elif opcode == "REALM_LIST":
                    pass
                else:
                    Logger.error(f'Unknown opcode: {opcode}')
            
        finally:
            Logger.info(f"Closed connection from {client_socket.getpeername()}")
            client_socket.close()

    @staticmethod
    def start(port):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", port))
        server.listen(5)
        Logger.info(f'Listening on port {port}')

        while True:
            client_socket, addr = server.accept()
            Logger.success(f'Accepted connection from {addr}')
            client_handler = threading.Thread(target=AuthServer.handle_client, args=(client_socket, config,))
            client_handler.start()
