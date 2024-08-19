#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-

from dataclasses import dataclass
from utils.Logger import Logger
from utils.opcodes import *
from server.auth.AuthProtocol import AuthLogonChallengeClient, AuthLogonChallengeServer, AuthLogonProofClient, AuthLogonProofServer, RealmListClient
import socket
import threading


logging_mask = 0x7f

def client_emulator(server, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((ip, port))

        sock.sendall()


    while True:
        data = source.recv(4096)

        if not data:
            break

        auth_opcode_name = opcodes.getCodeName(AuthCode, data[0])
        
        Logger.info(f"{direction} : OPCODE : {auth_opcode_name}")
        Logger.info(f"   Data: {data}")
        Logger.info(f"   Length: {len(data)}")

        if direction == "Client to Server" and auth_opcode_name == "AUTH_LOGON_CHALLENGE":
            decoded_data = AuthLogonChallengeClient.unpack(data)
            Logger.package(f'{decoded_data}', logging_mask)
        elif direction == "Server to Client" and auth_opcode_name == "AUTH_LOGON_CHALLENGE":
            decoded_data = AuthLogonChallengeServer.unpack(data)
            Logger.package(f'{decoded_data}', logging_mask)
        elif direction == "Client to Server" and auth_opcode_name == "AUTH_LOGON_PROOF":
            decoded_data = AuthLogonProofServer.unpack(data)
            Logger.package(f'{decoded_data}', logging_mask)
        elif direction == "Server to Client" and auth_opcode_name == "AUTH_LOGON_PROOF":
            decoded_data = AuthLogonProofServer.unpack(data)
            Logger.package(f'{decoded_data}', logging_mask)
        elif direction == "Client to Server" and auth_opcode_name == "REALM_LIST":
            # decoded_data = RealmListC.unpack(data)
            # print(f"   Decoded: {decoded_data}")

            decoded_data = RealmListClient.unpack(data)
            Logger.package(f'{decoded_data}', logging_mask)
        elif direction == "Server to Client" and auth_opcode_name == "REALM_LIST":
           # decoded_data = RealmListS.unpack(data)
           # print(f"   Decoded: {decoded_data}")
            """
            Server to Client : OPCODE : REALM_LIST
            Data: b'\x10.\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00Pandaria\x00192.168.11.30:8085\x00\x00\x00\x00\x00\x01\x01\x01\x10\x00'
            Length: 49

            Server to Client : OPCODE : REALM_LIST
            Data: b'\x10U\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00Pandaria\x00192.168.11.30:8085\x00\x00\x00\x00\x00\x01\x01\x01\x00\x00\x00Pandaria2\x00192.168.11.30:8085\x00\x00\x00\x00\x00\x00\x01\x02\x10\x00'
            Length: 88
            """

            pass

        destination.sendall(data)


if __name__ == "__main__":
    Logger.info(f'Mist of Pandaria 5.4.8 Client emulator')
    server = "192.168.11.30"
    port = 3724

    client_emulator(server, port)
    

