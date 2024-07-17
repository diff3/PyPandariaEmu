#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-


import hashlib
from database.AuthModel import *
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from utils.opcodes import *
import yaml
import random
from utils.Logger import Logger
import struct

from server.auth.Decoder import AuthLogonChallengeC, AuthLogonProofC


with open("etc/config.yaml", 'r') as file:
    config = yaml.safe_load(file)

realm_db_engine = create_engine(f'mysql+pymysql://{config["database"]["user"]}:{config["database"]["password"]}@{config["database"]["host"]}:{config["database"]["port"]}/auth?charset={config["database"]["charset"]}',
                                pool_pre_ping=True)
SessionHolder = scoped_session(sessionmaker(bind=realm_db_engine, autoflush=False))


class AuthProofData:
    def create_auth_proof(data):
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
        
        auth_db_session = SessionHolder()
        account = auth_db_session.query(Account).filter_by(username=data.I).first()
        auth_db_session.close()

        v_hex = account.v
        s_hex = account.s
        N_hex = config['crypto']['N']

        N = int(N_hex, 16)
        v = int(v_hex, 16)
        s = int(s_hex, 16)

        securityFlags = 0x00

        b = random.getrandbits(152)
        # b = 3381075083266726368626876785455561395178425281
        g = int(config['crypto']['g'])

        gmod = pow(g, b, N)
        B = ((v * 3) + gmod) % N

        unk3 = random.getrandbits(128)
        # unk3 = 190708628721133826782318909029779410613

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

        return pkt, b, B
    
class HandleProof:
    @staticmethod
    def check_proof(username, B, b, data):
        auth_db_session = SessionHolder()
        account = auth_db_session.query(Account).filter_by(username=username).first()
        # auth_db_session.close()

        _login = account.username

        v_hex = account.v
        s_hex = account.s
        N_hex = config['crypto']['N']
        A_hex = data.A[::-1].hex().upper()
        B_hex = hex(B)[2:]
        
        g = int(config['crypto']['g'])
        N = int(N_hex, 16)
        v = int(v_hex, 16)
        A = int(A_hex, 16)

        M1 = data.M1[::-1].hex().upper()

        # Calculate S
        sha1 = hashlib.sha1()
        sha1.update(bytes.fromhex(A_hex)[::-1])
        sha1.update(bytes.fromhex(B_hex)[::-1])
        u = int.from_bytes(sha1.digest(), byteorder='little')

        S = pow(A * pow(v, u, N), b, N)

        # Calculate K
        t1 = bytearray(16)
        t2 = bytearray(16)

        S_hex = hex(S)[2:]
        S_bytes = bytes.fromhex(S_hex)[::-1]

        for i in range(16):
            t1[i] = S_bytes[i * 2]
            t2[i] = S_bytes[i * 2 + 1]

        sha1 = hashlib.sha1()
        sha1.update(t1)
        t1h = sha1.digest()

        sha1 = hashlib.sha1()
        sha1.update(t2)
        t2h = sha1.digest()

        Kb = bytearray(40)

        for i in range(20):
            Kb[i * 2] = t1h[i]
            Kb[i * 2 + 1] = t2h[i]
        
        K_bytes= Kb[::-1]

        # Calculate t3
        sha1 = hashlib.sha1()
        sha1.update(N.to_bytes((N.bit_length() + 7) // 8, 'little'))
        hash = bytearray(sha1.digest())[::-1]

        sha1 = hashlib.sha1()
        sha1.update(g.to_bytes((g.bit_length() + 7) // 8, 'little'))
        digest = sha1.digest()[::-1]

        for i in range(20):
            hash[i] ^= digest[i]

        t3_bytes = hash

        # Calculate t4
        sha1 = hashlib.sha1()
        sha1.update(_login.encode('utf-8'))
        t4_bytes = sha1.digest()[::-1]

        # Calculate M
        A_bytes = bytes.fromhex(A_hex)
        B_bytes = bytes.fromhex(B_hex)
        s_bytes = bytes.fromhex(s_hex)
        
        sha1 = hashlib.sha1()
        sha1.update(t3_bytes[::-1])
        sha1.update(t4_bytes[::-1])
        sha1.update(s_bytes[::-1])
        sha1.update(A_bytes[::-1])
        sha1.update(B_bytes[::-1])
        sha1.update(K_bytes[::-1])
        M_bytes = sha1.digest()[::-1]

        # print(f'M     ={M_bytes.hex().upper()}')
        # print(f'M1    ={M1.upper()}')

        if M_bytes.hex().upper() == M1:
            # print("Found key")

            account.sessionkey = K_bytes.hex()
            auth_db_session.commit()
            auth_db_session.close()


            sha1 = hashlib.sha1()
            sha1.update(A_bytes[::-1])
            sha1.update(M_bytes[::-1])
            sha1.update(K_bytes[::-1])

            res = bytearray(32)
            pos = 0

            res[pos] = 1
            pos += 1
            res[pos] = 0
            pos += 1

            digest = sha1.digest()
            res[pos:pos+20] = digest
            pos += 20

            struct.pack_into('<I', res, pos, 0x800000)
            pos += 4
            struct.pack_into('<I', res, pos, 0)
            pos += 4
            struct.pack_into('<H', res, pos, 0)
            pkt = bytes(res)

            return pkt


class Password:

    @staticmethod
    def create_pass(username, password):
        username_pass = username.upper() + ":" + password.upper()
        return hashlib.sha1(username_pass.encode()).hexdigest().upper()