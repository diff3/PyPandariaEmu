#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
import yaml
from utils.opcodes.AuthProtocol import AuthLogonChallengeClient, AuthLogonChallengeServer, AuthLogonProofClient, AuthLogonProofServer, RealmListClient, AuthRecconectProofClient
from database.AuthModel import *
from utils.opcodes.AuthOpcodes import *
from utils.crypto.arc4_crypto import *
from utils.Logger import Logger
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session


with open("etc/config.yaml", 'r') as file:
    config = yaml.safe_load(file)

realm_db_engine = create_engine(
    f'mysql+pymysql://{config["database"]["user"]}:{config["database"]["password"]}@{config["database"]["host"]}:{config["database"]["port"]}/auth?charset={config["database"]["charset"]}',
        pool_pre_ping=True
    )

SessionHolder = scoped_session(sessionmaker(bind=realm_db_engine, autoflush=False))

logging_mask = 0x7f


def getUserSession(username):
    auth_db_session = SessionHolder()
    account = auth_db_session.query(Account).filter_by(username=username).first()
    auth_db_session.close()

    return bytes.fromhex(account.sessionkey)

def save_to_file(filename, header_data=None, K_value=None):
    with open(filename, "a") as file:
        if K_value:
            file.write(f"K content (hex): {K_value}\n")
        
        if header_data:
            file.write(f"Header content (hex): {header_data}\n")


def authserver_forward_data(source, destination, direction):
    while True:
        data = source.recv(4096)

        if not data:
            break

        auth_opcode_name = opcodes.getCodeName(AuthCode, data[0])
        
        if direction == "Client --> Server" and auth_opcode_name == "AUTH_LOGON_CHALLENGE":
            decoded_data = AuthLogonChallengeClient.unpack(data)
            Logger.info(f'{direction} Login Challange')
            Logger.package(f'{decoded_data}', logging_mask)
        elif direction == "Server --> Client" and auth_opcode_name == "AUTH_LOGON_CHALLENGE":
            Logger.info(f'{direction} Login Challange')
            decoded_data = AuthLogonChallengeServer.unpack(data)
            Logger.package(f'{decoded_data}', logging_mask)
        elif direction == "Client --> Server" and auth_opcode_name == "AUTH_LOGON_PROOF":
            Logger.info(f'{direction} Login Proof')
            decoded_data = AuthLogonProofServer.unpack(data)
            Logger.package(f'{decoded_data}', logging_mask)
        elif direction == "Server --> Client" and auth_opcode_name == "AUTH_LOGON_PROOF":
            Logger.info(f'{direction} Login Proof')
            decoded_data = AuthLogonProofServer.unpack(data)
            Logger.package(f'{decoded_data}', logging_mask)
        elif direction == "Client --> Server" and auth_opcode_name == "REALM_LIST":
            Logger.info(f'{direction} Realm List')
            decoded_data = RealmListClient.unpack(data)
            Logger.package(f'{decoded_data}', logging_mask)
        elif direction == "Server to Client" and auth_opcode_name == "REALM_LIST":
            Logger.info(f'{direction} Realm List')
           # decoded_data = RealmListS.unpack(data)
           # print(f"   Decoded: {decoded_data}")
            pass

        destination.sendall(data)

def worldserver_forward_data(source, destination, direction):
    K = getUserSession("admin")[::-1].hex()
    # save_to_file("logs/arc4_test_client_data.txt", None, K)
    # save_to_file("logs/arc4_test_server_data.txt", None, K)

    IH = handle_input_header()
    
    IH.initArc4(K, None)
    encoded_trafic = False

    while True:
        
        data = b''
        
        while True:
            chunk = source.recv(4096)
            data += chunk
            if len(chunk) < 4096:
                break  

        if len(data) <= 0:
            break

        header_data = data[:4]

        if header_data.hex() == "a302b200" or header_data.hex() == "29004909":
            Logger.info(f"{direction} Initializing encryption")
            IH.initArc4(K, direction)
            encoded_trafic = True
        elif encoded_trafic:
        # elif encoded_trafic and not direction == 'Client --> Server':
        # elif encoded_trafic and not direction == 'Server --> Client':
            data_multi_header = data

            while True:
                headers_list = []
                payload = None 

                header_encryped = data_multi_header[:4]

                try:
                    if direction == "Client --> Server":
                        decrypted_header = IH.decryptRecv(header_encryped)
                    else:
                        decrypted_header = IH.encryptSend(header_encryped)

                    header = IH.unpack_data(decrypted_header)
                except Exception as e:
                    Logger.info(f"Error processing data: {e}")
                    break

                if len(data_multi_header) == 4 + header.size:
                    payload = data_multi_header[4:header.size]
            
                headers_list.append((decrypted_header.hex(), header.size, payload))
                
                data_multi_header = data_multi_header[4 + header.size:]
        
                if not data_multi_header:
                    break

            for header_hex, size, payload in headers_list:
                header = IH.unpack_data(bytes.fromhex(header_hex))
                opname = IH.getOpCodeName(header.cmd)
                Logger.info(f"{direction} [hex]: {header_hex}, size: {size} CMD: {hex(header.cmd)[2:]} ({header.cmd})    \t{opname}")
                
                '''if direction == "Client --> Server":
                    save_to_file("logs/arc4_test_client_data.txt",header_hex , None)
                else:    
                    save_to_file("logs/arc4_test_server_data.txt",header_hex , None)'''

        elif not encoded_trafic:
            # Logger.info(f'{data.decode('ascii')}')
            Logger.info(f'{direction} {data}')
        else:
            Logger.error(f'{direction} {data}')

        
        try:
            destination.sendall(data)
        except BrokenPipeError:
            Logger.success("Connection closed")

def handle_client(client_socket, remote_host, remote_port, handler_type):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((remote_host, remote_port))
    
    if handler_type == "Authserver":
        Logger.success("USING AUTHSERVER HANDLER")
        client_to_server = threading.Thread(target=authserver_forward_data, args=(client_socket, server_socket, "Client --> Server"))
        server_to_client = threading.Thread(target=authserver_forward_data, args=(server_socket, client_socket, "Server --> Client"))
    elif handler_type == "Worldserver":
        Logger.success("USING WORLDSERVER HANDLER")
        client_to_server = threading.Thread(target=worldserver_forward_data, args=(client_socket, server_socket, "Client --> Server"))
        server_to_client = threading.Thread(target=worldserver_forward_data, args=(server_socket, client_socket, "Server --> Client"))
    else:
        Logger.error("Unknown handler type!")
        client_socket.close()
        server_socket.close()
        return
    
    client_to_server.start()
    server_to_client.start()
    
    client_to_server.join()
    server_to_client.join()
    
    client_socket.close()
    server_socket.close()

def start_proxy(local_host, local_port, remote_host, remote_port, handler_type):
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.bind((local_host, local_port))
    proxy_socket.listen(5)
        
    Logger.info(f"{handler_type} proxy listening at {local_host}:{local_port}")
        
    threading.Thread(target=accept_connections, args=(proxy_socket, remote_host, remote_port, handler_type)).start()

def accept_connections(proxy_socket, remote_host, remote_port, handler_type):
    while True:
        client_socket, addr = proxy_socket.accept()
        Logger.success(f"Accepted connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, remote_host, remote_port, handler_type))
        client_handler.start()


if __name__ == "__main__":
    Logger.info(f"Mist of Pandaria 5.4.8 ProxyServer")
    
    type = "Authserver"
    auth_local_host = "0.0.0.0"
    auth_local_port = 3722
    auth_remote_host = "192.168.11.30"
    auth_remote_port = 3724
    threading.Thread(target=start_proxy, args=(auth_local_host, auth_local_port, auth_remote_host, auth_remote_port, type)).start()

    type = "Worldserver"
    world_local_host = "0.0.0.0"
    world_local_port = 8084
    world_remote_host = "192.168.11.30"
    world_remote_port = 8085
    threading.Thread(target=start_proxy, args=(world_local_host, world_local_port, world_remote_host, world_remote_port, type)).start()