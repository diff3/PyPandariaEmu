#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-

from dataclasses import dataclass
from utils.Logger import Logger
from utils.world.opcodes import *
# from utils.opcodes import opcodes
from server.auth.AuthProtocol import AuthLogonChallengeClient, AuthLogonChallengeServer, AuthLogonProofClient, AuthLogonProofServer, RealmListClient
import socket
import threading


logging_mask = 0x7f

def forward_data(source, destination, direction):
    while True:
        data = source.recv(4096)

        if not data:
            break

        opcode = data[:2]
        opcode_name = opcodes.getCodeName(WorldOpcodes, opcode)

        Logger.info(f"{direction}")
        Logger.info(f"   opcode: {opcode}")
        Logger.info(f"   name: {opcode_name}")
        Logger.info(f"   Length: {len(data)}")
        Logger.info(f"   Data: {data}")

        destination.sendall(data)

def handle_client(client_socket, remote_host, remote_port):
    # Connect to the actual server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((remote_host, remote_port))
    
    # Create threads to forward data in both directions
    client_to_server = threading.Thread(target=forward_data, args=(client_socket, server_socket, "Client to Server"))
    server_to_client = threading.Thread(target=forward_data, args=(server_socket, client_socket, "Server to Client"))
    
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
        
    Logger.info(f'Proxy listening on {local_host}:{local_port}')
        
    threading.Thread(target=accept_connections, args=(proxy_socket, remote_host, remote_port)).start()

def accept_connections(proxy_socket, remote_host, remote_port):
    while True:
        client_socket, addr = proxy_socket.accept()
        Logger.success("Accepted connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, remote_host, remote_port))
        client_handler.start()

if __name__ == "__main__":
    Logger.info(f'Mist of Pandaria 5.4.8 proxy decoder')
    local_host = "0.0.0.0"
    local_port = 8084
    remote_host = "192.168.11.30"
    remote_port = 8085
    
    start_proxy(local_host, local_port, remote_host, remote_port)

