#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from database.AuthModel import *
from server.auth.AuthProtocol import AuthLogonChallengeServer, AuthLogonProofServer
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from utils.Logger import Logger
from utils.opcodes import AuthCode, AuthResult
import hashlib
import random
import struct
import yaml


with open("etc/config.yaml", 'r') as file:
    config = yaml.safe_load(file)

realm_db_engine = create_engine(
        f'mysql+pymysql://{config["database"]["user"]}:{config["database"]["password"]}@{config["database"]["host"]}:{config["database"]["port"]}/auth?charset={config["database"]["charset"]}',
        pool_pre_ping=True
    )
SessionHolder = scoped_session(sessionmaker(bind=realm_db_engine, autoflush=False))


class AuthProofData:

    @staticmethod
    def create_auth_proof(data):        
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
        g = int(config['crypto']['g'])

        gmod = pow(g, b, N)
        B = ((v * 3) + gmod) % N

        unk3 = random.getrandbits(128)

        data = {
            'cmd': AuthCode.AUTH_LOGON_CHALLENGE,
            'error': 0x00,
            'success': AuthResult.WOW_SUCCESS,
            'B': B.to_bytes(32, byteorder='little'),
            'l': 1,
            'g': g,
            'blob': 32,
            'N': N.to_bytes(32, byteorder='little'),
            's': s.to_bytes(32, byteorder='little'),
            'unk3': unk3.to_bytes(16, byteorder='little'),
            'securityFlags': securityFlags
        }

        return AuthLogonChallengeServer.pack(data), b, B
    
class HandleProof:

    @staticmethod
    def check_proof(username, B, b, data):
        auth_db_session = SessionHolder()
        account = auth_db_session.query(Account).filter_by(username=username).first()

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

        # Cryptaded password from client
        M1 = data.M1[::-1].hex().upper()

        # Calculate u for S calculation
        try:
            sha1 = hashlib.sha1()
            sha1.update(bytes.fromhex(A_hex)[::-1])
            sha1.update(bytes.fromhex(B_hex)[::-1])
            u = int.from_bytes(sha1.digest(), byteorder='little')
        except:
            Logger.warning("A or B are not hex number")
            return 0

        S = pow(A * pow(v, u, N), b, N)

        # Calculate K
        t1 = bytearray(16)
        t2 = bytearray(16)

        try:
            S_hex = hex(S)[2:]
            S_bytes = bytes.fromhex(S_hex)[::-1]
        except:
            Logger.warning("S is not a hex number")
            return 0

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

        if M_bytes.hex().upper() == M1:
            Logger.debug("Found key")

            # Update session for user
            account.sessionkey = K_bytes.hex()
            auth_db_session.commit()
            auth_db_session.close()

            # Calculate M2
            sha1 = hashlib.sha1()
            sha1.update(A_bytes[::-1])
            sha1.update(M_bytes[::-1])
            sha1.update(K_bytes[::-1])
            digest = sha1.digest()

            data = {
                'cmd': AuthCode.AUTH_LOGON_PROOF,
                'error': 0,
                'M2': digest,
                'unk1': 0x800000,
                'unk2': 0,
                'unk3': 0
            }

            return AuthLogonProofServer.pack(data)


class RealmList:

    @staticmethod
    def create_realmlist():
        auth_db_session = SessionHolder()
        realmData = auth_db_session.query(Realmlist).first()
        auth_db_session.close()

        RealmListSize = 1

        pkt = bytearray()
        pkt.append(0x00)
        pkt.append(realmData.icon) # Not working, only normal or pvp
        pkt.append(realmData.allowedSecurityLevel) # It's lock or not lock to level.
        pkt.append(realmData.flag) # Not sure, it's mark realm with red
        pkt.extend(realmData.name.encode('utf-8') + b'\x00')
        pkt.extend(f'{realmData.address}:{realmData.port}'.encode('utf-8') + b'\x00')
   
        pkt.extend(struct.pack('<f', realmData.population)) # Not working correct, it showing low on 1, medium on 2 and high above.
        pkt.append(realmData.timezone) 
        pkt.append(0x01) # View or hide realm
        pkt.append(0x01) # Think it's mark realm
        pkt.append(0x10) # Fix for 2.x and 3.x clients
        pkt.append(0x00) # As above

        header = bytearray()
        header.append(AuthCode.REALM_LIST)  
        realmlistsizebuffer = struct.pack('>i', RealmListSize)
        header.extend(struct.pack('<h', len(pkt) + len(realmlistsizebuffer) + 1))
        header.append(0x00) 
        header.extend(struct.pack('>i', RealmListSize))

        data = bytes(header + pkt)

        # Test data
        # data = b'\x101\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00Skyfire_MoP\x00192.168.11.30:8085\x00\x00\x00\x00\x00\x00\x01\x01\x10\x00'

        return data

class Password:

    @staticmethod
    def create_pass(username, password):
        username_pass = username.upper() + ":" + password.upper()
        return hashlib.sha1(username_pass.encode()).hexdigest().upper()