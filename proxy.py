#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import time
import threading
from database.AuthModel import *
from utils.ConfigLoader import ConfigLoader
from utils.crypto.arc4_crypto import *
from utils.opcodes.AuthOpcodes import *
from utils.opcodes.AuthProtocol import AuthLogonChallengeClient, AuthLogonChallengeServer, AuthLogonProofClient, AuthLogonProofServer, RealmListClient, AuthRecconectProofClient
from utils.opcodes.WorldOpcodes import *
from utils.Logger import Logger
from utils.DatabaseConnection import DatabaseConnection


config = ConfigLoader.load_config()
DatabaseConnection.initialize()

sessions = {}


def clean_old_sessions(timeout=600): 
    current_time = time.time()
    to_remove = []
    
    for client_ip, session_data in sessions.items():
        if current_time - session_data["timestamp"] > timeout:
            to_remove.append(client_ip)
    
    for client_ip in to_remove:
        del sessions[client_ip]
        Logger.info(f"Removed expired session for IP {client_ip}")

def save_to_file(filename, header_data=None, K_value=None):
    with open(filename, "a") as file:
        if K_value:
            file.write(f"K content (hex): {K_value}\n")
        
        if header_data:
            file.write(f"Header content (hex): {header_data}\n")

def parse_multi_header_payloads(data_multi_header, IH, encoded_trafic, direction):
    headers_list = []

    while data_multi_header:
        #if len(data_multi_header) < 4:
         #   print("[ERROR] Remaining data too small for a header")
          #  break
        
        payload = None
        header = data_multi_header[:4]
        orig = header

        if b'WORLD OF WARCRAFT' in data_multi_header: 
            headers_list.append((orig, None, data_multi_header))
            break

        if encoded_trafic:
            if direction == "Client --> Server":
                header = IH.decrypt_recv(header)
            else:      
                header = IH.encrypt_send(header)

            header = IH.unpack_data(header)
        else:
            cmd = int(header[2:4][::-1].hex(), 16)
            size = int(header[0:2][::-1].hex(), 16)
            header = IH.unpack_data(header)
            header.cmd = cmd
            header.size = size
            
        payload = data_multi_header[4:4 + header.size]
        headers_list.append((orig, header, payload))
        data_multi_header = data_multi_header[4 + header.size:]

        if not data_multi_header:
            break

    return headers_list

def authserver_forward_data(source, destination, direction):
    global sessions

    while True:
        data = source.recv(4096)

        if not data:
            break

        auth_opcode_name = AuthOpcodes.getCodeName(AuthCode, data[0])
        
        if direction == "Client --> Server" and auth_opcode_name == "AUTH_LOGON_CHALLENGE":
            decoded_data = AuthLogonChallengeClient.unpack(data)

            username = decoded_data.I
            client_ip, _ = source.getpeername()
            print(client_ip)

            clean_old_sessions()

            sessions[client_ip] = {
                "username": username,
                "timestamp": time.time()
            }
            print(sessions)


            Logger.info(f'{direction} Login Challange')
            Logger.package(f'{decoded_data}')
        elif direction == "Server --> Client" and auth_opcode_name == "AUTH_LOGON_CHALLENGE":
            Logger.info(f'{direction} Login Challange')
            decoded_data = AuthLogonChallengeServer.unpack(data)
            Logger.package(f'{decoded_data}')
        elif direction == "Client --> Server" and auth_opcode_name == "AUTH_LOGON_PROOF":
            Logger.info(f'{direction} Login Proof')
            decoded_data = AuthLogonProofServer.unpack(data)
            Logger.package(f'{decoded_data}')
        elif direction == "Server --> Client" and auth_opcode_name == "AUTH_LOGON_PROOF":
            Logger.info(f'{direction} Login Proof')
            decoded_data = AuthLogonProofServer.unpack(data)
            Logger.package(f'{decoded_data}')
        elif direction == "Client --> Server" and auth_opcode_name == "REALM_LIST":
            Logger.info(f'{direction} Realm List')
            decoded_data = RealmListClient.unpack(data)
            Logger.package(f'{decoded_data}')
        elif direction == "Server to Client" and auth_opcode_name == "REALM_LIST":
            Logger.info(f'{direction} Realm List')
           # decoded_data = RealmListS.unpack(data)
           # print(f"   Decoded: {decoded_data}")
            pass

        destination.sendall(data)


def print_package_information(headers_list, direction):
    for orig, header, payload in headers_list:
        if not header:
            Logger.info(f"{direction} [raw] {payload}")
            break

        if direction == "Client --> Server":
            opname = WorldOpcodes.getClientOpCodeName(header.cmd)
        else:      
            opname = WorldOpcodes.getServerOpCodeName(header.cmd)

        Logger.info(f"{direction} [hex]: {orig.hex()}, size: {header.size:<6} CMD: {hex(header.cmd)[2:]:<4} ({header.cmd})\t{opname: <20}")

        if config['Logging']['opcodes']:
            if hex(header.cmd)[2:] in config['Logging']['opcodes']:
                Logger.debug(f"{payload}")

def worldserver_forward_data(source, destination, direction):
    global sessions

    client_ip, _ = source.getpeername() if direction == "Client --> Server" else destination.getpeername()
    print(client_ip)
    clean_old_sessions()
    print(sessions)
    
    if client_ip in sessions:
        username = sessions[client_ip]["username"]
    else:
        Logger.warning(f'No session found for {direction} traffic from IP {client_ip}')
        
    
    IH = Arc4CryptoHandler()
    # IH.init_arc4(K)
    K = str()
    
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

        
        if data:
            print(data)

        headers_list = parse_multi_header_payloads(data, IH, encoded_trafic, direction)
        # print_package_information(headers_list, direction)

        for orig, header, payload in headers_list:
            if not header:
                Logger.info(f"{direction} [raw] {payload}")
                break

            if direction == "Client --> Server":
                opname = WorldOpcodes.getClientOpCodeName(header.cmd)
            else:      
                opname = WorldOpcodes.getServerOpCodeName(header.cmd)

            Logger.info(f"{direction} [hex]: {orig.hex()}, size: {header.size:<6} CMD: {hex(header.cmd)[2:]:<4} ({header.cmd})\t{opname: <20}")

            if config['Logging']['opcodes']:
                if hex(header.cmd)[2:] in config['Logging']['opcodes']:
                    Logger.debug(f"{payload}")
        
        if not encoded_trafic:
            cmd = int(data[2:4][::-1].hex(), 16)

            if cmd == WorldServerOpcodes.SMSG_AUTH_CHALLENGE:
                K = DatabaseConnection.get_mirrored_sessionkey_by_username(username=username)
                Logger.info(f"Initializing encryption: Server --> Client")      
                IH.init_arc4(K)
                print(K)
                encoded_trafic = True
            elif cmd == WorldClientOpcodes.CMSG_AUTH_SESSION:
                K = DatabaseConnection.get_mirrored_sessionkey_by_username(username=username)
                Logger.info(f"Initializing encryption: Client --> Server")
                IH.init_arc4(K)
                encoded_trafic = True

        try:
            destination.sendall(data)
        except BrokenPipeError:
            # Logger.success("Connection closed")
            pass
            
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
    auth_local_host = config['proxyserver']['auth_host']
    auth_local_port = config['proxyserver']['auth_port']
    auth_remote_host = config['proxyserver']['auth_remote_host']
    auth_remote_port = config['proxyserver']['auth_remote_port']
    threading.Thread(target=start_proxy, args=(auth_local_host, auth_local_port, auth_remote_host, auth_remote_port, type)).start()

    type = "Worldserver"
    world_local_host = config['proxyserver']['world_host']
    world_local_port = config['proxyserver']['world_port']
    world_remote_host = config['proxyserver']['world_remote_host']
    world_remote_port = config['proxyserver']['world_remote_port']
    threading.Thread(target=start_proxy, args=(world_local_host, world_local_port, world_remote_host, world_remote_port, type)).start()