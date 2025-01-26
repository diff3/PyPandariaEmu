#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger
import socket
import threading
from handlers.AuthHandler import *
import utils.opcodes.AuthOpcodes as opcodes
import struct
from utils.DatabaseConnection import DatabaseConnection
from utils.opcodes.WorldOpcodes import *

config = ConfigLoader.load_config()

class BitReader:
    """Class to read bits from a byte array."""
    def __init__(self, data):
        self.data = data
        self.byte_pos = 0
        self.bit_pos = 0
        self.cur_byte = self.data[self.byte_pos]

    def read_bit(self):
        """Reads a single bit from the byte array."""
        bit = (self.cur_byte >> (7 - self.bit_pos)) & 1
        self.bit_pos += 1

        if self.bit_pos > 7:  # Move to the next byte
            self.bit_pos = 0
            self.byte_pos += 1
            if self.byte_pos < len(self.data):
                self.cur_byte = self.data[self.byte_pos]

        return bit

    def read_bits(self, num_bits):
        """Reads multiple bits from the byte array."""
        value = 0
        for _ in range(num_bits):
            bit = self.read_bit()
            value = (value << 1) | bit
        return value


def parse_raw_data(raw_data):
    """
    Parses raw binary data to extract session information.

    Args:
        raw_data (bytes): The raw packet data.

    Returns:
        None
    """
    # Initialize digest and extract values
    digest = [0] * 20
    digest[18] = f"{raw_data[10]:02X}"
    digest[14] = f"{raw_data[11]:02X}"
    digest[3] = f"{raw_data[12]:02X}"
    digest[4] = f"{raw_data[13]:02X}"
    digest[0] = f"{raw_data[14]:02X}"
    virtual_realm_id = int.from_bytes(raw_data[15:19], byteorder='little')
    digest[11] = f"{raw_data[19]:02X}"
    client_seed = int.from_bytes(raw_data[20:24], byteorder='little')
    digest[19] = f"{raw_data[24]:02X}"

    # Skip uint8 x2
    digest[2] = f"{raw_data[27]:02X}"
    digest[9] = f"{raw_data[28]:02X}"
    digest[12] = f"{raw_data[29]:02X}"

    # Skip uint64 and uint32
    digest[16] = f"{raw_data[42]:02X}"
    digest[5] = f"{raw_data[43]:02X}"
    digest[6] = f"{raw_data[44]:02X}"
    digest[8] = f"{raw_data[45]:02X}"
    client_build = int.from_bytes(raw_data[46:48], byteorder='little')
    digest[17] = f"{raw_data[48]:02X}"
    digest[7] = f"{raw_data[49]:02X}"
    digest[13] = f"{raw_data[50]:02X}"
    digest[15] = f"{raw_data[51]:02X}"
    digest[1] = f"{raw_data[52]:02X}"
    digest[10] = f"{raw_data[53]:02X}"

    # Extract addon size and data
    addon_size = int.from_bytes(raw_data[54:58], byteorder='little')
    addon_data_start = 58
    addon_data_end = addon_data_start + addon_size
    addon_data = raw_data[addon_data_start:addon_data_end]

    # Remaining data after addonData
    remaining_data = raw_data[addon_data_end:]

    # Extract account name length and account name
    bit_reader = BitReader(remaining_data)
    bit_reader.read_bit()  # Skip the first flag bit
    account_name_length = bit_reader.read_bits(11)
    account_name = remaining_data[2:2 + account_name_length].decode('utf-8')

    return digest, account_name


class WorldServer:

    @staticmethod
    def client_handler(client_socket):
            K = str()
            encryption = False

        # try:

            start_session = b'0\x00WORLD OF WARCRAFT CONNECTION - SERVER TO CLIENT\x00'
            client_socket.send(start_session)

            while True:
                print("loop")
                data = b''
        
                while True:
                    chunk = client_socket.recv(4096)
                    data += chunk

                    if len(chunk) < 4096:
                        break

                    if len(data) <= 0:
                        break

                if not data: break

                print(data)
                header_raw = data[:4]

                if encryption == False:
                    cmd = int(header_raw[2:4][::-1].hex(), 16)
                    opname = WorldOpcodes.getClientOpCodeName(cmd)
                    print(opname)

                    if data == b'0\x00WORLD OF WARCRAFT CONNECTION - CLIENT TO SERVER\x00':
                        print("Sent SMSG_AUTH_CHALLANGE")
                        # send SMSG_AUTH_CHALLANGE

                        payload = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xde\x88\xbe\x0c'
                        header = "29004909"
                        package = bytes.fromhex(header) + payload
                        client_socket.send(package)

                    if opname == "CMSG_AUTH_SESSION":
                        digest, username = parse_raw_data(data[:4])
                        K = DatabaseConnection.get_mirrored_sessionkey_by_username(username=username)

                        print(K)
                        IH.init_arc4(K)

                        payload = b'\x80\x00\x04,*\x00\x00,\x00\x00\x00\x00\x00<\x01\x00\x00\x00Skyfire MoPSkyfireMoP\x00\x06\x00\x05\x00\x02\x00\x07\x03\t\x00\x01\x00\x08\x04\x18\x01\x0b\x03\x16\x01\n\x00\x04\x00\x03\x04\x19\x04\x1a\x04\n\x00\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x07\x00\x08\x00\t\x00\x0b\x02\x06\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c'
                        header = IH.pack_data('aba', len(payload))
                        header = IH.encrypt_send(header)
                        package = header + payload
                        client_socket.send(package)

                        print("Sent SMSG_AUTH_RESPONSE")


                        # send SMSG_AUTH_RESPONSE
                        # send SMSG_ADDON_INFO
                        # send SMSG_CLIENTCACHE_VERSION
                        # send SMSG_TUTORIAL_FLAGS
                        # send SMSG_SET_TIME_ZONE_INFORMATION
                        pass
                
                else:
                    header = IH.decrypt_recv(header_raw)
                
                    if data == "CMSG_READY_FOR_ACCOUNT_DATA_TIMES":
                        # send SMSG_ACCOUNT_DATA_TIMES
                        pass
                    elif data == "CMSG_ENUM_CHARACTERS":
                        # send SMSG_ENUM_CHARACTERS_RESULT
                        pass
                    elif data == "CMSG_BATTLE_PAY_GET_PURCHASE_LIST":
                        pass
                    elif data == "CMSG_LOG_DISCONNECT":
                        pass 
                    else:
                        pass 

                    # if reply:
                        # client_socket.send(response)
        
        # except Exception as e:
          #  Logger.warning(f'Unknown handler error {e}')
                    
        # finally:
          #   Logger.success(f"Closed connection from {client_socket.getpeername()}")
            # client_socket.close()

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


