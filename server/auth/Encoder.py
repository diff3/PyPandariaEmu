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

        # b = random.getrandbits(152)
        b = 3381075083266726368626876785455561395178425281
        g = config['crypto']['g']

        gmod = pow(g, b, N)
        B = ((v * 3) + gmod) % N

        # unk3 = random.getrandbits(128)
        unk3 = 190708628721133826782318909029779410613

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
    def check_proof(username, B, b, old_data, data):
        auth_db_session = SessionHolder()
        account = auth_db_session.query(Account).filter_by(username=old_data.I).first()
        auth_db_session.close()

        _login = username

        try:
            lp = AuthLogonProofC.unpack(data)
            Logger.debug(f'{lp}')
        except:
            print("AuthLogonProofC is wrong size")

        A = int.from_bytes(lp.A[::-1], byteorder='big')

        if not A:
            return 
            
        N = int(config['crypto']['N'], 16)
        g = config['crypto']['g']
        v = int(account.v, 16)

        sha1 = hashlib.sha1()
        sha1.update(A.to_bytes((A.bit_length() + 7) // 8, 'big'))
        sha1.update(B.to_bytes((B.bit_length() + 7) // 8, 'big'))
        u_byte = sha1.digest()
        
        u = int.from_bytes(u_byte, byteorder='big')
        
        S = pow(A * pow(u, v, N), b, N)

        t = bytearray(32)  
        t1 = bytearray(16)  
        vK = bytearray(40) 

        t = S.to_bytes(32, byteorder='little')
        
        for i in range(16):
            t1[i] = t[i * 2]

        sha1 = hashlib.sha1()
        sha1.update(t1)
        digest = sha1.digest()

        for i in range(20):
            vK[i * 2] = digest[i]

        for i in range(16):
            t1[i] = t[i * 2 + 1]

        sha1 = hashlib.sha1()
        sha1.update(t1[:16])
        digest = sha1.digest()

        for i in range(20):
            vK[i * 2 + 1] = digest[i]

        K = int.from_bytes(vK[::-1], byteorder='big')

        hash = bytearray(20) 

        sha1 = hashlib.sha1()
        sha1.update(N.to_bytes((N.bit_length() + 7) // 8, 'big'))
        digest = sha1.digest()

        hash[:20] = digest[:20]

        sha1 = hashlib.sha1()
        sha1.update(g.to_bytes((g.bit_length() + 7) // 8, 'big'))
        digest = sha1.digest()

        for i in range(20):
            hash[i] ^= digest[i]

        t3 = int.from_bytes(hash[::-1], byteorder='big')


        login_str = _login.encode('utf-8')  # Konvertera användarnamnet till bytes om det är en sträng


        
        sha1 = hashlib.sha1()
        # sha1.update(t1[_login])
        sha1.update(login_str)  # Uppdatera SHA1-hashen med användarnamnet
        digest = sha1.digest()

        t4 = bytearray(len(digest))
        t4[:len(digest)] = digest[:len(digest)]

        sha1 = hashlib.sha1()
        sha1.update(t3.to_bytes((t3.bit_length() + 7) // 8, 'big'))
        sha1.update(t4)
        sha1.update(S.to_bytes((S.bit_length() + 7) // 8, 'big'))
        sha1.update(A.to_bytes((A.bit_length() + 7) // 8, 'big'))
        sha1.update(B.to_bytes((B.bit_length() + 7) // 8, 'big'))
        sha1.update(K.to_bytes((K.bit_length() + 7) // 8, 'big'))
        digest = sha1.digest()
        # M = int.from_bytes(digest, byteorder='big')
        M = digest
        
        print(f'M={M}')
        # print(data)

        hex_str = ''.join(f'{byte:02x}' for byte in data)
        # print(hex_str)

        integer_value = int(hex_str, 16)
        
        print(f'M1={integer_value}')


class Password:

    @staticmethod
    def create_pass(username, password):
        username_pass = username.upper() + ":" + password.upper()
        return hashlib.sha1(username_pass.encode()).hexdigest().upper()