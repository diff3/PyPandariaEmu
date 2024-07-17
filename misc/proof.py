#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-

from utils.Logger import Logger
import random

from dataclasses import dataclass
import struct

"""
Added realm "Pandaria" at 192.168.11.30:8085.
Added realm "Pandaria2" at 192.168.11.30:8085.
N as hexadecimal String: 894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7
N as decimal String: 62100066509156017342069496140902949863249758336000796928566441170293728648119
s as hexadecimal String: DCCB88FE78D06F584597861AF39CDFEE0D4FD5EFB2961615E99FAEAB0AA16B93
s as decimal String: 99868442140521454595396142365126655019671128310006691081165431423435614022547
v as hexadecimal String: 5CFB50BF6DD9D76C56A2F72709C1DE7E0683C12E84EF552720E3CAF640384F5A
v as decimal String: 42056817983546093453784660706891819426739125358988168067690591070286645841754
b as hexadecimal String: 979CD6A6747EDA0BFDF842375339ADA421CBC1
b as decimal String: 3381075083266726368626876785455561395178425281
g as hexadecimal String: 07
g as decimal String: 7
gmod as hexadecimal String: 17C32508AB55C7A0E84FB1405D11A0877F35E7DECC4B52184BCD57004A54FA35
gmod as decimal String: 10747986293385006102790148357052558705040139330201388125310521098654847400501
B as hexadecimal String: 1C1E4E89E120A72E70DDDF9F284A9B5B82BDC84CDB9A946E57FFB2D4B680B0D5
B as decimal String: 12718307225711251780005138195922117258757998735164298471249411968927327629525
unk3 as hexadecimal String: 8F792557C85767DB61F6E2775C628EB5
unk3 as decimal String: 190708628721133826782318909029779410613
Updating Realm List...


SkyFire
   Data: b'\x00\x00\x00\xd5\xb0\x80\xb6\xd4\xb2\xffWn\x94\x9a\xdbL\xc8\xbd\x82[\x9bJ(\x9f\xdf\xddp.\xa7 \xe1\x89N\x1e\x1c\x01\x07 \xb7\x9b>*\x87\x82<\xab\x8f^\xbf\xbf\x8e\xb1\x01\x08SP\x06)\x8b[\xad\xbd[S\xe1\x89^dK\x89\x93k\xa1\n\xab\xae\x9f\xe9\x15\x16\x96\xb2\xef\xd5O\r\xee\xdf\x9c\xf3\x1a\x86\x97EXo\xd0x\xfe\x88\xcb\xdc\xb5\x8eb\\w\xe2\xf6a\xdbgW\xc8W%y\x8f\x00'

PyPandariaEmu
   Data: b"\x00\x00\x00\x1c\x1eN\x89\xe1 \xa7.p\xdd\xdf\x9f(J\x9b[\x82\xbd\xc8L\xdb\x9a\x94nW\xff\xb2\xd4\xb6\x80\xb0\xd5\x01\x07 \x89Kd^\x89\xe1S[\xbd\xad[\x8b)\x06PS\x08\x01\xb1\x8e\xbf\xbf^\x8f\xab<\x82\x87*>\x9b\xb7\\\xfbP\xbfm\xd9\xd7lV\xa2\xf7\'\t\xc1\xde~\x06\x83\xc1.\x84\xefU\' \xe3\xca\xf6@8OZ\x8fy%W\xc8Wg\xdba\xf6\xe2w\\b\x8e\xb5\x00")

"""

WOW_SUCCESS = 0x00

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


class opcodes:
    
    @staticmethod
    def getCode(opcode):

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




class AuthProofData:
    def create_auth_proof():
        """
        Creates an authentication proof for the given data.

        Args:
            data (dict): A dictionary containing the following keys:
                - 'I' (str): The username.

        Returns:
            bytearray: A bytearray representing the authentication proof.

        Description:
            This static method retrieves the account information from the database based on the provided username.
            It then generates a random number 'b' and calculates 'gmod' using the formula ((v * 3) + gmod) % N.
            The calculated 'B' is used to create the authentication proof, which is a bytearray containing the following fields:
                - AUTH_LOGON_CHALLENGE (byte)
                - 0x00 (byte)
                - WOW_SUCCESS (byte)
                - B (32 bytes)
                - 1 (byte)
                - g (byte)
                - 32 (byte)
                - N (32 bytes)
                - s (32 bytes)
                - unk3 (16 bytes)
                - securityFlags (byte)

            The authentication proof is returned as a bytearray.
        """
        


        N_hex = "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7"
        s_hex = "DCCB88FE78D06F584597861AF39CDFEE0D4FD5EFB2961615E99FAEAB0AA16B93"
        v_hex = "5CFB50BF6DD9D76C56A2F72709C1DE7E0683C12E84EF552720E3CAF640384F5A"
        g = 7
        
        Logger.debug(f'N_hex = {N_hex}')
        Logger.debug(f's_hex = {s_hex}')
        Logger.debug(f'v_hex = {v_hex}')
        Logger.debug(f'g = {g}')

        N = int(N_hex, 16)
        v = int(v_hex, 16)
        s = int(s_hex, 16)

        Logger.debug(f'v = {v}')
        Logger.debug(f'N = {N}')

        securityFlags = 0x00
        
        Logger.debug(f'flag= {securityFlags}')
     
        # b = random.getrandbits(152)
        b = 3381075083266726368626876785455561395178425281
        
        gmod = pow(g, b, N)
        B = ((v * 3) + gmod) % N

        Logger.debug(f'b = {b}')
        Logger.debug(f'gmod = {gmod}')
        Logger.debug(f'B = {B}')

        # s_bytes = bytes.fromhex(s_hex)[::-1]
        # Logger.debug(f's_bytes = {s_bytes}')

        # unk3 = random.getrandbits(128)
        unk3 = 190708628721133826782318909029779410613
        Logger.debug(f'unk3 = {unk3}')

        pkt = bytearray()
        pkt.append(AUTH_LOGON_CHALLENGE)
        pkt.append(0x00)
        pkt.append(WOW_SUCCESS)
        pkt.extend(B.to_bytes(32, byteorder='little'))
        pkt.append(1)
        pkt.append(g)
        pkt.append(32)
        pkt.extend(N.to_bytes(32, byteorder='little'))
        pkt.extend(s.to_bytes(32, byteorder='little'))
        pkt.extend(unk3.to_bytes(16, byteorder='little'))
        pkt.append(securityFlags)

        print(pkt)


        return pkt, b, B
    

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


if __name__ == "__main__":   
      response, global_b, global_B = AuthProofData.create_auth_proof()
      data = AuthLogonChallengeS.unpack(response)
      print(data)

      response = b'\x00\x00\x00\xd5\xb0\x80\xb6\xd4\xb2\xffWn\x94\x9a\xdbL\xc8\xbd\x82[\x9bJ(\x9f\xdf\xddp.\xa7 \xe1\x89N\x1e\x1c\x01\x07 \xb7\x9b>*\x87\x82<\xab\x8f^\xbf\xbf\x8e\xb1\x01\x08SP\x06)\x8b[\xad\xbd[S\xe1\x89^dK\x89\x93k\xa1\n\xab\xae\x9f\xe9\x15\x16\x96\xb2\xef\xd5O\r\xee\xdf\x9c\xf3\x1a\x86\x97EXo\xd0x\xfe\x88\xcb\xdc\xb5\x8eb\\w\xe2\xf6a\xdbgW\xc8W%y\x8f\x00'
      data = AuthLogonChallengeS.unpack(response)
      print(data)

"""
AuthLogonChallengeS(
    cmd=0, 
    error=0, 
    sucess=0, 
    B=b'\x1c\x1eN\x89\xe1 \xa7.p\xdd\xdf\x9f(J\x9b[\x82\xbd\xc8L\xdb\x9a\x94nW\xff\xb2\xd4\xb6\x80\xb0\xd5', 
    l=1, 
    g=7, 
    blob=32, 
    N=b'\x89Kd^\x89\xe1S[\xbd\xad[\x8b)\x06PS\x08\x01\xb1\x8e\xbf\xbf^\x8f\xab<\x82\x87*>\x9b\xb7', 
    s=b"\\\xfbP\xbfm\xd9\xd7lV\xa2\xf7'\t\xc1\xde~\x06\x83\xc1.\x84\xefU' \xe3\xca\xf6@8OZ", 
    unk3=b'\x8fy%W\xc8Wg\xdba\xf6\xe2w\\b\x8e\xb5', 
    securityFlags=0
    )

AuthLogonChallengeS(
    cmd=0, 
    error=0, 
    sucess=0, 
    B=b'\xd5\xb0\x80\xb6\xd4\xb2\xffWn\x94\x9a\xdbL\xc8\xbd\x82[\x9bJ(\x9f\xdf\xddp.\xa7 \xe1\x89N\x1e\x1c', 
    l=1, 
    g=7, 
    blob=32, 
    N=b'\xb7\x9b>*\x87\x82<\xab\x8f^\xbf\xbf\x8e\xb1\x01\x08SP\x06)\x8b[\xad\xbd[S\xe1\x89^dK\x89', 
    s=b'\x93k\xa1\n\xab\xae\x9f\xe9\x15\x16\x96\xb2\xef\xd5O\r\xee\xdf\x9c\xf3\x1a\x86\x97EXo\xd0x\xfe\x88\xcb\xdc', 
    unk3=b'\xb5\x8eb\\w\xe2\xf6a\xdbgW\xc8W%y\x8f', 
    securityFlags=0
    )
"""

print(b'\x1c\x1eN\x89\xe1 \xa7.p\xdd\xdf\x9f(J\x9b[\x82\xbd\xc8L\xdb\x9a\x94nW\xff\xb2\xd4\xb6\x80\xb0\xd5'.hex())
print(b'\xd5\xb0\x80\xb6\xd4\xb2\xffWn\x94\x9a\xdbL\xc8\xbd\x82[\x9bJ(\x9f\xdf\xddp.\xa7 \xe1\x89N\x1e\x1c'.hex())

bytes_data = b'\xb7\x9b>*\x87\x82<\xab\x8f^\xbf\xbf\x8e\xb1\x01\x08SP\x06)\x8b[\xad\xbd[S\xe1\x89^dK\x89'

# Konvertera från little-endian byte-sträng till hexadecimal
hex_data = bytes_data[::-1].hex()

print(hex_data)



"""
   SkyFire
   Decoded: AuthLogonProofC(cmd=1, A=b'\x12"\x05\xf1\x95D\x92t\xdeq\xca\xc1\xb8\x97\xc9)\xb1&Q\x8f\xbc2\\k2\xd7\xbf\xc2\xecag\x18', M1=b'_\x9e\nV9\x8dTN\xfb\x10J4\xf5\xe8\xfc-LW\x11\xfb', crc_hash=b':\xf1\xe5|\xd2Y\x87\xacFny\x9c\xb5\r\xc6\x9d\x92h_\xe3', number_of_keys=0, security_flags=0)
   Decoded: AuthLogonProofC(cmd=1, A=b'\xc0Z\\\xfa\xbd\x0f\x05\x06)[\x11]\xbb\xa4cz\x14\xfe\xb5j\x89\xf6\xf8\x12Oy\xa5\xd4\xbf8]\x0c', M1=b'\x18\xf4\x83\xb2*Sz\x80Pi\xc9\xd2\x12m\xfa\x1d\xa7wL<', crc_hash=b'\x82|\xd3\x7f3\x14\x11\xb4\x0bz\xdc\xa1\xd5b\xda\x96\xbc\x1f\x0f\xff', number_of_keys=0, security_flags=0)

   PyPandariaEmu
   Decoded: AuthLogonProofC(cmd=1, A=b"\x08u\x12/\xfc`p'\x86pL\x02\x15\x9d*\x93x\xe8\xd5\xbc,\xf4kQ\xd3\xabp\x14'\xb3aC", M1=b'\x832\xf3\x17\xb4\x98gl\xf6\x8f\xbe\x99\xb5\xf0?9\x18\x90\x98\xc6', crc_hash=b'\xd2#\xd9\xf9\x14\xd7\xf8\xf6\x9c[\xdd\x17\xccR%>\xaf\x83Uk', number_of_keys=0, security_flags=0)
   Devoded: AuthLogonProofC(cmd=1, A=b'\xf1\x00ctE\xa6m\x0e\x83/\x9e}>\x18yG/\x0c\xe2Rb\xf1O\x18x\xa6\xe5\xed\x83VD\x1b', M1=b'\xa4s\xcak\x93$\xb6m\x8b\xf8\x9c\x11\x91+q5\x0c\x9ct\x19', crc_hash=b'MS\xb5\x12?\xb2G\xd4Nc\xbc\x0c\xff\xda\xad\x01C\x97\xc6c', number_of_keys=0, security_flags=0)

"""


data = b'\x01~i\xfd\xe5\xcf\x00=(42\xaf\xe6t\xfe\xb4w\xccC\xe2'
hex_data = data[::-1].hex()
print(hex_data)
