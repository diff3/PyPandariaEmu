#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading

def start_proxy(local_host, local_port, remote_host, remote_port):
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.bind((local_host, local_port))
    proxy_socket.listen(5)
        
    print(f"Proxy listening at {local_host}:{local_port}")
        
    threading.Thread(target=accept_connections, args=(proxy_socket, remote_host, remote_port)).start()

def accept_connections(proxy_socket, remote_host, remote_port):
    while True:
        client_socket, addr = proxy_socket.accept()

        print(f"Accepted connection from {addr}")
        
        client_handler = threading.Thread(target=handle_client, args=(client_socket, remote_host, remote_port))
        client_handler.start()

def handle_client(client_socket, remote_host, remote_port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((remote_host, remote_port))
    
    client_to_server = threading.Thread(target=forward_data, args=(client_socket, server_socket, "Client --> Server"))
    server_to_client = threading.Thread(target=forward_data, args=(server_socket, client_socket, "Server --> Client"))
    
    client_to_server.start()
    server_to_client.start()
    
    client_to_server.join()
    server_to_client.join()
    
    client_socket.close()
    server_socket.close()

def forward_data(source, destination, direction):
    while True:
        
        data = b''
        
        while True:
            chunk = source.recv(4096)
            data += chunk
            if len(chunk) < 4096:
                break  

        if len(data) <= 0:
            break

        print(f'{direction} {data}')

        
        try:
            destination.sendall(data)
        except BrokenPipeError:
            print("Connection closed")


if __name__ == "__main__":
    print(f"Mist of Pandaria 5.4.8 ProxyServer")
    
    local_host = "0.0.0.0"
    local_port = 3722
    remote_host = "192.168.11.30"
    remote_port = 3724
    threading.Thread(target=start_proxy, args=(local_host, local_port, remote_host, remote_port)).start()

