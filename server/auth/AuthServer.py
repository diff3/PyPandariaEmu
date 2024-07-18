#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from server.auth.AuthHandler import AuthProofData, HandleProof, RealmList
from server.auth.AuthProtocol import AuthLogonChallengeClient, AuthLogonChallengeServer, AuthLogonProofClient, AuthLogonProofServer, RealmListClient
from utils.Logger import Logger
from utils.opcodes import *
import socket
import threading


class AuthServer:    

    @staticmethod
    def handle_client(client_socket):
        global_b = None
        global_B = None
        username = None

        try:
            while True:
                data = client_socket.recv(1024)
                
                if not data:
                    break

                opcode = opcodes.getCode(AuthCode, data[0])
                Logger.info(f'{opcode} ({client_socket.getpeername()[0]})')

                if opcode == "AUTH_LOGON_CHALLENGE":
                    decoded_data = AuthLogonChallengeClient.unpack(data)
                    Logger.package(f'{decoded_data}')
    
                    response, global_b, global_B = AuthProofData.create_auth_proof(decoded_data)
                    Logger.package(f'{AuthLogonChallengeServer.unpack(response)}')

                    if not decoded_data.I or len(decoded_data.I) <= 0:
                        Logger.warning(f'{opcode}: user not found')
                        break

                    username = decoded_data.I

                    if response: client_socket.send(response)
                elif opcode == "AUTH_LOGON_PROOF": 
                    decoded_data = AuthLogonProofClient.unpack(data)
                    Logger.package(f'{decoded_data}')
                    
                    response = HandleProof.check_proof(username, global_B, global_b, decoded_data)
                    Logger.package(f'{AuthLogonProofServer.unpack(response)}')

                    if response: client_socket.send(response)
                elif opcode == "REALM_LIST":
                    decoded_data = RealmListClient.unpack(data)
                    Logger.package(f'{decoded_data}')

                    if len(data) < 5:
                        Logger.warning(f'{opcode}: data got wrong size')
                        break

                    response = RealmList.create_realmlist()
                    Logger.debug(f'{response}')

                    if response: client_socket.send(response)
                else:
                    Logger.error(f'Unknown opcode: {opcode}')
            
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
            client_handler = threading.Thread(target=AuthServer.handle_client, args=(client_socket,))
            client_handler.start()
