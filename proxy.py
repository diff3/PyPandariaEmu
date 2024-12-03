#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
# import binascii
import yaml
from misc.wow_mop_arc4 import *
from plugins.mop_18414.database.AuthModel import *
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


# Definiera autentiseringskoderna
AUTH_LOGON_CHALLENGE = 0x00
AUTH_LOGON_PROOF = 0x01
AUTH_RECONNECT_CHALLENGE = 0x02
AUTH_RECONNECT_PROOF = 0x03
REALM_LIST = 0x10
XFER_INITIATE = 0x30
XFER_DATA = 0x31
XFER_ACCEPT = 0x32
XFER_RESUME = 0x33
XFER_CANCEL = 0x34


# Funktion för att få namn på autentiseringskoder
def get_auth_opcode_name(opcode):
    if opcode == AUTH_LOGON_CHALLENGE:
        return "AUTH_LOGON_CHALLENGE"
    elif opcode == AUTH_LOGON_PROOF:
        return "AUTH_LOGON_PROOF"
    elif opcode == AUTH_RECONNECT_CHALLENGE:
        return "AUTH_RECONNECT_CHALLENGE"
    elif opcode == AUTH_RECONNECT_PROOF:
        return "AUTH_RECONNECT_PROOF"
    elif opcode == REALM_LIST:
        return "REALM_LIST"
    elif opcode == XFER_INITIATE:
        return "XFER_INITIATE"
    elif opcode == XFER_DATA:
        return "XFER_DATA"
    elif opcode == XFER_ACCEPT:
        return "XFER_ACCEPT"
    elif opcode == XFER_RESUME:
        return "XFER_RESUME"
    elif opcode == XFER_CANCEL:
        return "XFER_CANCEL"
    else:
        return f"Unknown Opcode: {opcode}"

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

def forward_data(source, destination, direction):
    K = getUserSession("admin")[::-1].hex()
    save_to_file("arc4_test_client_data.txt", None, K)
    save_to_file("arc4_test_server_data.txt", None, K)

    IH = handle_input_header()
    
    IH.initArc4(K, None)
    encoded_trafic = False

    try:
        headers_list = []
        
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
                Logger.info("Initializing encryption")
                IH.initArc4(K, direction)
                encoded_trafic = True
            elif encoded_trafic:
                # elif encoded_trafic and not direction == 'Client --> Server':
                # elif encoded_trafic and not direction == 'Server --> Client':
                data_multi_header = data

                while True:
                    payload = None 

                    header_encryped = data_multi_header[:4]

                    try:
                        if direction == "Client --> Server":
                            decrypted_header = IH.decryptRecv(header_encryped)
                        else:
                            decrypted_header = IH.encryptSend(header_encryped)

                        header = IH.unpack_data(decrypted_header)
                    except Exception as e:
                        print(f"Error processing data: {e}")
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
                    print(f"{direction} [hex]: {header_hex}, size: {size} CMD: {hex(header.cmd)[2:]} ({header.cmd})   \t{opname}")

                headers_list = []

            destination.sendall(data)
    except KeyboardInterrupt:
        print("Avslutar programmet...")    
    
        client_file.close()
        server_file.close()

def handle_client(client_socket, remote_host, remote_port):
    # Connect to the actual server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((remote_host, remote_port))
    
    # Create threads to forward data in both directions
    client_to_server = threading.Thread(target=forward_data, args=(client_socket, server_socket, "Client --> Server"))
    server_to_client = threading.Thread(target=forward_data, args=(server_socket, client_socket, "Server --> Client"))
    
    client_to_server.start()
    server_to_client.start()
    
    client_to_server.join()
    server_to_client.join()
    
    client_socket.close()
    server_socket.close()

def start_proxy(local_host, local_port, remote_host, remote_port):
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.bind((local_host, local_port))
    proxy_socket.listen(5)
        
    Logger.info(f"Mist of Pandaria 5.4.8 ProxyServer")
    Logger.info(f"Listening at {local_host}:{local_port}")
        
    threading.Thread(target=accept_connections, args=(proxy_socket, remote_host, remote_port)).start()

def accept_connections(proxy_socket, remote_host, remote_port):
    while True:
        client_socket, addr = proxy_socket.accept()
        Logger.success(f"Accepted connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, remote_host, remote_port))
        client_handler.start()


if __name__ == "__main__":
    local_host = "0.0.0.0"
    local_ports = 8084
    remote_host = "192.168.11.30"
    remote_port = 8085
    
    start_proxy(local_host, local_ports, remote_host, remote_port)