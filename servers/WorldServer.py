#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from utils.Logger import Logger
import socket
import threading
import yaml
from handlers.AuthHandler import *
import utils.opcodes.auth as opcodes

with open("etc/config.yaml", 'r') as file:
    config = yaml.safe_load(file)


class WorldServer:

    @staticmethod
    def client_handler(client_socket):

        # b'\x08\x00\xb3\x10\x00\x00\x0e\x00\x00\x00'
        try:

            respons = b'0\x00WORLD OF WARCRAFT CONNECTION - SERVER TO CLIENT\x00'
            client_socket.send(respons)

            while True:
                data = client_socket.recv(1024)

                if not data: break
                print(data)



                # Data: b'0\x00WORLD OF WARCRAFT CONNECTION - CLIENT TO SERVER\x00'

                
                # opcode = opcodes.opcodes.getCodeName(opcodes.AuthCode, data[0])
                # handler = opcode_handlers.get(opcode, client_socket)

                """if handler:
                    Logger.info(f'{client_socket.getpeername()[0]}:{opcode}')
                    Logger.info(f'{data}')
                    error, response = handler(data)
                else:
                    Logger.warning(f'Opcode: {opcode} is unknown') 

                if not error == 0:
                    Logger.warning(f"Closed connection from {client_socket.getpeername()}")
                    client_socket.close()

                client_socket.send(response)"""
        
        except:
            Logger.warning(f'Unknown handler error')
                    
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
            client_handler = threading.Thread(target=WorldServer.client_handler, args=(client_socket,))
            client_handler.start()


