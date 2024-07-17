#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-

from dataclasses import dataclass
import struct
import socket
import threading
from authcodes import AuthResult, LoginResult, is_accepted_client_build, get_build_info


@dataclass
class AuthLogonChallengeC:
    cmd: int
    error: int
    size: int
    gamename: str
    version1: int
    version2: int
    version3: int
    build: int
    platform: str
    os: str
    country: str
    timezone_bias: int
    ip: str
    I_len: int
    I: str
    
    @classmethod
    def unpack(cls, data):
        fixed_size_format = '<BBH4sBBBH4s4s4sIIB'
        fixed_size_length = struct.calcsize(fixed_size_format)
    
        unpacked_data = list(struct.unpack(fixed_size_format, data[:fixed_size_length]))
        unpacked_data[3] = unpacked_data[3].decode('utf-8').rstrip('\x00')
        unpacked_data[8] = unpacked_data[8].decode('utf-8').rstrip('\x00').strip('\x00')[::-1]
        unpacked_data[9] = unpacked_data[9].decode('utf-8').rstrip('\x00').strip('\x00')[::-1]
        unpacked_data[10] = unpacked_data[10][::-1].decode('utf-8').rstrip('\x00')
        unpacked_data[12] = socket.inet_ntoa(struct.pack('<I', unpacked_data[12]))
        unpacked_data.append(data[fixed_size_length:].decode('utf-8'))
    
        return cls(*unpacked_data)


@dataclass
class AuthLogonChallengeS:
    cmd: int
    error: int
    sucess: int
    B: str
    l: int
    g: int
    blob: str
    N: str
    s: str
    unk3: int
    securityFlags: int 

    @classmethod
    def unpack(cls, data):
        fixed_size_format = 'BBB32sBBB32s32s16sB'
        fixed_size_length = struct.calcsize(fixed_size_format)
    
        unpacked_data = list(struct.unpack(fixed_size_format, data[:fixed_size_length]))
        return cls(*unpacked_data)


@dataclass 
class AuthLogonProofC:
    cmd: int
    A: str
    M1: str
    crc_hash: str
    number_of_keys: int
    security_flags: int 

    @classmethod
    def unpack(cls, data):
        fixed_size_format = 'B32s20s20sBB'
        fixed_size_length = struct.calcsize(fixed_size_format)
    
        unpacked_data = list(struct.unpack(fixed_size_format, data[:fixed_size_length]))
        return cls(*unpacked_data)


@dataclass
class AuthLogonProofS:
    cmd: int
    error: int
    M2: str
    unk1: int
    unk2: int
    unk3: int

    @classmethod
    def unpack(cls, data):
        fixed_size_format = 'BB20sIHH'
        fixed_size_length = struct.calcsize(fixed_size_format)

        unpacked_data = list(struct.unpack(fixed_size_format, data[:fixed_size_length]))
        return cls(*unpacked_data)


@dataclass
class RealmListC:
    cmd: int

    @classmethod
    def unpack(cls, data):
        fixed_size_format = 'B'
        cmd = struct.unpack(fixed_size_format, data[:1])[0]

        return get_auth_opcode_name(cmd)


@dataclass
class RealmListS:
    cmd: int
    id: int
    name: str
    icon: int
    flag: int
    timezone: float
    allowedSecurityLevel: int
    popu: float
    address: str
    build: int

    @classmethod
    def unpack(cls, data):
#        fixed_size_format = 'BB20sIHH'
 #       fixed_size_length = struct.calcsize(fixed_size_format)

        fixed_file_format = 'IB{}sBBBf{}sI'.format(len(data) - 23, len(data) - 23 - 6)

        # Paketera datan enligt formatet
        id, len_name, len_address = struct.unpack(fixed_file_format[:6], data[:6])
        name_bytes = data[6:6 + len_name]
        address_bytes = data[6 + len_name:6 + len_name + len_address]
        icon, flag, timezone, security_level, popu, len_address = struct.unpack(fixed_file_format[-6:], data[-6:])

        # Avkoda byte-strängar till vanliga strängar
        name = name_bytes.decode('utf-8')
        address = address_bytes.decode('utf-8')

        # Skriv ut den avkodade datan
        print(f"ID: {id}")
        print(f"Name: {name}")
        print(f"Address: {address}")
        print(f"Icon: {icon}")
        print(f"Flag: {flag}")
        print(f"Timezone: {timezone}")
        print(f"Security Level: {security_level}")
        print(f"Population: {popu}")




        unpacked_data = list(struct.unpack(fixed_size_format, data[:fixed_size_length]))
        return cls(*unpacked_data)



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
        return "XFER_DATA"
    elif opcode == XFER_ACCEPT:
        return "XFER_ACCEPT"
    elif opcode == XFER_RESUME:
        return "XFER_RESUME"
    elif opcode == XFER_CANCEL:
        return "XFER_CANCEL"
    elif opcode == REALM_LIST:
        return "REALM_LIST"
    else:
        return f"Unknown Opcode: {opcode}"


def forward_data(source, destination, direction):
    while True:
        data = source.recv(4096)
        if len(data) == 0:
            break
        opcode = data[0]
        auth_opcode_name = get_auth_opcode_name(opcode)
        
        print(f"{direction} : OPCODE : {auth_opcode_name}")
        print(f"   Data: {data}")
        print(f"   Length: {len(data)}")

        if direction == "Client to Server" and auth_opcode_name == "AUTH_LOGON_CHALLENGE":
            decoded_data = AuthLogonChallengeC.unpack(data)
            print(f"   Decoded: {decoded_data}")
        elif direction == "Server to Client" and auth_opcode_name == "AUTH_LOGON_CHALLENGE":
            decoded_data = AuthLogonChallengeS.unpack(data)
            print(f"   Decoded: {decoded_data}")
        elif direction == "Client to Server" and auth_opcode_name == "AUTH_LOGON_PROOF":
            decoded_data = AuthLogonProofC.unpack(data)
            print(f"   Decoded: {decoded_data}")
        elif direction == "Server to Client" and auth_opcode_name == "AUTH_LOGON_PROOF":
            # decoded_data = AuthLogonProofS.unpack(data)
            # print(f"   Decoded: {decoded_data}")
            pass
        elif direction == "Client to Server" and auth_opcode_name == "REALM_LIST":
            decoded_data = RealmListC.unpack(data)
            print(f"   Decoded: {decoded_data}")
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

def start_proxy(local_host, local_ports, remote_host, remote_port):
    for local_port in local_ports:
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.bind((local_host, local_port))
        proxy_socket.listen(5)
        
        print(f"Proxy listening on {local_host}:{local_port}")
        
        threading.Thread(target=accept_connections, args=(proxy_socket, remote_host, remote_port)).start()

def accept_connections(proxy_socket, remote_host, remote_port):
    while True:
        client_socket, addr = proxy_socket.accept()
        print(f"Accepted connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, remote_host, remote_port))
        client_handler.start()

if __name__ == "__main__":
    local_host = "0.0.0.0"
    local_ports = [3722]
    remote_host = "192.168.11.30"
    remote_port = 3724
    
    start_proxy(local_host, local_ports, remote_host, remote_port)

