#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-

import socket
import threading
import yaml
from server.auth.Decoder import AuthLogonChallengeC, AuthLogonProofC
from server.auth.Encoder import AuthProofData, HandleProof
from utils.Logger import Logger
from utils.opcodes import *

import hashlib
from database.AuthModel import *
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

with open("etc/config.yaml", 'r') as file:
    config = yaml.safe_load(file)


realm_db_engine = create_engine(f'mysql+pymysql://{config["database"]["user"]}:{config["database"]["password"]}@{config["database"]["host"]}:{config["database"]["port"]}/auth?charset={config["database"]["charset"]}',
                                pool_pre_ping=True)
SessionHolder = scoped_session(sessionmaker(bind=realm_db_engine, autoflush=False))


class AuthServer:    

    @staticmethod
    def handle_client(client_socket, config):
        global_b = None
        global_B = None
        username = None
        decoded_data = None

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
                    username = decoded_data.I
                    Logger.debug(f'{response}')

                    client_socket.send(response)
                elif opcode == "AUTH_LOGON_PROOF": 
                    Logger.info(f'Received AUTH_LOGON_PROOF')
                    HandleProof.check_proof(username, global_B, global_b, decoded_data, data)

                    # Logger.info(f'Sending AUTH_LOGON_PROOF to client')
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
