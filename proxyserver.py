#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import signal
import socket
import sys
import threading
import traceback
from database.DatabaseConnection import DatabaseConnection
from protocol.Arc4Crypto import Arc4CryptoHandler
from protocol.opcodes.AuthSessionParser import AuthSessionParser
from protocol.opcodes.AuthOpcodes import AuthOpcodes, AuthCode
from protocol.opcodes.AuthProtocol import (
    AuthLogonChallengeClient, 
    AuthLogonChallengeServer, 
    AuthLogonProofServer, 
    AuthRecconectProofClient,
    RealmListClient,
    printDataRealm,
    printData
    )
from manager.Sessions import SessionManager
from protocol.opcodes.WorldOpcodes import WorldClientOpcodes, WorldOpcodes
from utils.APISingleton import APISingleton
from utils.BaseServerTemplates import BaseProxy
from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger


config = ConfigLoader.load_config()
DatabaseConnection.initialize()


class AuthProxy(BaseProxy):
    """
    Handles authentication-related proxy communication between the client and the authentication server.

    This class forwards authentication packets, decodes known authentication opcodes,
    and logs relevant packet information.
    """
    
    def forward_data(self, source_socket: socket.socket, destination_socket: socket.socket, direction: str) -> None:
        """
        Forwards data between the client and authentication server while processing authentication-related packets.
        """
                       
        while not self.stop_event.is_set():
            try:
                data = source_socket.recv(4096)

                if not data:
                    break


                auth_opcode_name = AuthOpcodes.getCodeName(AuthCode, data[0])

                unpack_mapping = {
                    (BaseProxy.DIRECTION_CLIENT_SERVER, "AUTH_LOGON_CHALLENGE"): AuthLogonChallengeClient,
                    (BaseProxy.DIRECTION_SERVER_CLIENT, "AUTH_LOGON_CHALLENGE"): AuthLogonChallengeServer,
                    (BaseProxy.DIRECTION_CLIENT_SERVER, "AUTH_LOGON_PROOF"): AuthLogonProofServer,
                    (BaseProxy.DIRECTION_SERVER_CLIENT, "AUTH_LOGON_PROOF"): AuthLogonProofServer,
                    (BaseProxy.DIRECTION_CLIENT_SERVER, "AUTH_RECONNECT_CHALLENGE"): printData,
                    (BaseProxy.DIRECTION_SERVER_CLIENT, "AUTH_RECONNECT_CHALLENGE"): printData,
                    (BaseProxy.DIRECTION_CLIENT_SERVER, "REALM_LIST"): RealmListClient,
                    (BaseProxy.DIRECTION_SERVER_CLIENT, "REALM_LIST"): printDataRealm,
                }

                # Process known authentication packets
                if (direction, auth_opcode_name) in unpack_mapping:
                    handler_class = unpack_mapping[(direction, auth_opcode_name)]
                    decoded_data = handler_class.unpack(data)

                    Logger.info(f'{direction} {auth_opcode_name}')
                    
                    if decoded_data:
                        Logger.package(f'{decoded_data}')
                else:
                    Logger.warning(f'Unknown auth_opcode_name: {auth_opcode_name} for direction {direction}')

                destination_socket.sendall(data)
            except Exception as e:
                error_details = traceback.format_exc()
                Logger.error(f"Connection error in {self.__class__.__name__}: {e}\n{error_details}")
        
        return None


class WorldProxy(BaseProxy):
    """
    Handles world server proxy communication between the client and world server.
    This class ensures proper encryption initialization and manages secure data transmission.
    """
    
    def initialize_encryption(
        self, 
        session_manager: object, 
        client_ip_address: str, 
        connection_direction: str, 
        is_encryption_active: bool, 
        arc4_handler: object) -> bool:
        
        """
        Enables encryption if not already active.
        """
        
        if is_encryption_active:
            return is_encryption_active  

        username = session_manager.get_username(client_ip_address)
        if username:
            K = DatabaseConnection.get_mirrored_sessionkey_by_username(username=username)
            Logger.info(f"Initializing encryption: {connection_direction}")
            arc4_handler.init_arc4(K)
            is_encryption_active = True
        return is_encryption_active

    def handle_auth_session(
        self, 
        session_manager: object, 
        raw_data: bytes, 
        client_ip_address: str, 
        arc4_handler: object) -> bool:
        
        """
        Handles CMSG_AUTH_SESSION by extracting the username and initializing encryption.
        """
        
        parser = AuthSessionParser(raw_data)
        parsed_result = parser.parse()
        username = parsed_result.get('username')

        if username:
            session_manager.add_session(client_ip_address, username)
            session_key = DatabaseConnection.get_mirrored_sessionkey_by_username(username=username)
            Logger.info(f"Initializing encryption: {BaseProxy.DIRECTION_CLIENT_SERVER}")
            arc4_handler.init_arc4(session_key)
            return True
        
        return False  

    def parse_multi_header_payloads(
        self, 
        raw_data: bytes, 
        arc4_handler: object, 
        is_encryption_active: bool, 
        connection_direction: str) -> list:
        
        """
        Parses multiple headers and payloads from raw data.
        """
        
        headers_list = []

        while raw_data:
            payload = None
            header = raw_data[:4]
            orig = header

            if b'WORLD OF WARCRAFT' in raw_data: 
                headers_list.append((orig, None, raw_data))
                break

            if is_encryption_active:
                if connection_direction == BaseProxy.DIRECTION_CLIENT_SERVER:
                    header = arc4_handler.decrypt_recv(header)
                else:      
                    header = arc4_handler.encrypt_send(header)

                header = arc4_handler.unpack_data(header)
            else:
                cmd = int(header[2:4][::-1].hex(), 16)
                size = int(header[0:2][::-1].hex(), 16)
                header = arc4_handler.unpack_data(header)
                header.cmd = cmd
                header.size = size
                
            payload = raw_data[4:4 + header.size]
            headers_list.append((orig, header, payload))
            raw_data = raw_data[4 + header.size:]

            if not raw_data:
                break

        return headers_list

    def process_data(
            self, 
            raw_data: bytes, 
            connection_direction: str, 
            arc4_handler: object, 
            is_encryption_active: bool) -> list:
            
            """
            Parses and logs incoming packets.
            """
            
            global config             
            headers_list = self.parse_multi_header_payloads(raw_data, arc4_handler, is_encryption_active, connection_direction)
            
            for original_header, parsed_header, payload in headers_list:
                if not parsed_header:
                    Logger.info(f"{connection_direction} [raw] {payload}")
                    break

                if connection_direction == BaseProxy.DIRECTION_CLIENT_SERVER:
                    opcode_name = WorldOpcodes.getClientOpCodeName(parsed_header.cmd)
                else:      
                    opcode_name = WorldOpcodes.getServerOpCodeName(parsed_header.cmd)

                Logger.info(
                    f"{connection_direction} [hex]: {original_header.hex()}, size: {parsed_header.size:<6} "
                    f"CMD: {hex(parsed_header.cmd)[2:]:<4} ({parsed_header.cmd})\t{opcode_name: <20}"
                )

                # Send Logger msg to API Server
                asyncio.run(self.api_client.send_log("INFO",
                    f"{connection_direction} [hex]: {original_header.hex()}, size: {parsed_header.size:<6} CMD: {hex(parsed_header.cmd)[2:]:<4} ({parsed_header.cmd})\t{opcode_name: <20}"
                ))

                if config['Logging']['opcodes'] and hex(parsed_header.cmd)[2:] in config['Logging']['opcodes']:
                    Logger.debug(f"{payload}")
                elif config['Logging']['opcodes'] == 'all':
                    Logger.debug(f"{payload}")

            return headers_list

    def forward_data(
        self, 
        source_socket: socket.socket, 
        destination_socket: socket.socket, 
        connection_direction: str) -> None:
        
        """
        Decrypts, logs, and forwards data between client and server.
        """
        
        is_encryption_active = False
        session_manager = SessionManager()
        arc4_handler = Arc4CryptoHandler()
        self.api_client = APISingleton()

        while not self.stop_event.is_set():
            try:
                raw_data = b''
                while True:
                    chunk = source_socket.recv(4096)
                    raw_data += chunk
                    if len(chunk) < 4096 or len(raw_data) == 0:
                        break

                if not raw_data:
                    break 

                client_ip_address, _ = source_socket.getpeername()

                if connection_direction == BaseProxy.DIRECTION_SERVER_CLIENT:
                    is_encryption_active = self.initialize_encryption(
                        session_manager, client_ip_address, connection_direction, is_encryption_active, arc4_handler
                    )

                self.process_data(raw_data, connection_direction, arc4_handler, is_encryption_active)

                if not is_encryption_active:
                    cmd = int(raw_data[2:4][::-1].hex(), 16)
                    parsed_raw_data = raw_data[4:]

                    if cmd == WorldClientOpcodes.CMSG_AUTH_SESSION:
                        is_encryption_active = self.handle_auth_session(
                            session_manager, parsed_raw_data, client_ip_address, arc4_handler
                        )

                destination_socket.sendall(raw_data)

            except Exception as e:
                error_details = traceback.format_exc()
                Logger.error(f"Connection error in {self.__class__.__name__}: {e}\n{error_details}")
                
        Logger.success(f"User {client_ip_address} disconected.")
        
        return None


if __name__ == "__main__":
    
    stop_event = threading.Event()

    def handle_sigint(signal, frame):
        """Gracefully shuts down the server on Ctrl+C."""
        Logger.info("Shutting down servers...")
        stop_event.set()

    signal.signal(signal.SIGINT, handle_sigint)

    Logger.info("Mist of Pandaria 5.4.8 ProxyServer")

    # Initialize and start the authentication proxy
    auth_proxy = AuthProxy(
        local_host=config['proxyserver']['auth_host'], 
        local_port=config['proxyserver']['auth_port'], 
        remote_host=config['proxyserver']['auth_remote_host'], 
        remote_port=config['proxyserver']['auth_remote_port'], 
        stop_event=stop_event
    )
    
    auth_thread = threading.Thread(target=auth_proxy.start, daemon=True)
    auth_thread.start()

    # Initialize and start the world proxy
    world_proxy = WorldProxy(
        local_host=config['proxyserver']['world_host'], 
        local_port=config['proxyserver']['world_port'], 
        remote_host=config['proxyserver']['world_remote_host'],
        remote_port=config['proxyserver']['world_remote_port'], 
        stop_event=stop_event
    )
    
    world_thread = threading.Thread(target=world_proxy.start, daemon=True)
    world_thread.start()

    try:
        # Keep the main thread alive while both proxies run
        auth_thread.join()
        world_thread.join()
    except KeyboardInterrupt:
        Logger.info("Exiting...")
        sys.exit(0)
