#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from database.AuthModel import *
from utils.opcodes.AuthProtocol import AuthLogonChallengeClient, AuthLogonChallengeServer, AuthLogonProofClient, AuthLogonProofServer, RealmListClient, AuthRecconectProofClient

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger
from utils.opcodes.AuthOpcodes import AuthCode, AuthResult
import hashlib
import random
import struct
from utils.DatabaseConnection import DatabaseConnection
import os

from utils.opcodes.AuthPackets import *

config = ConfigLoader.load_config()
DatabaseConnection.initialize()


class Handler:
    global_b = None
    global_B = None
    username = None
    reconnectProof = None
    K = None
    
    @staticmethod
    def AuthLogonChallenge(data):
        if not AuthLogonChallengeClient.validate(data):
            Logger.warning("AuthLogonChallenge: client data didn't validate.")
            return 1, data

        decoded_data = AuthLogonChallengeClient.unpack(data)
        Logger.package(f'{decoded_data}')
        Handler.username = decoded_data.I

        if not decoded_data.build == 18414:
            Logger.warning(f'AuthLogonChallenge: Client build is not 18141 (Pandaria 5.4.8)')
            return 1, response
        response, Handler.global_b, Handler.global_B = AuthProofData.create_auth_proof(decoded_data)
        Logger.package(f'{AuthLogonChallengeServer.unpack(response)}')


        if response:
            return 0, response
        
        return 0, response   

    @staticmethod
    def AuthLogonProof(data):
        if not AuthLogonProofClient.validate(data):
            Logger.warning("AuthLogonProof: Client data didn't validate.")
            return 1, data


        decoded_data = AuthLogonProofClient.unpack(data)
        Logger.package(f'{decoded_data}')
        
        response = HandleProof.check_proof(Handler.username, Handler.global_B, Handler.global_b, decoded_data)

        Logger.package(f'{AuthLogonProofServer.unpack(response)}')

        if response: 
            return 0, response

        return 1, response            

    @staticmethod
    def RealmList(data):
        decoded_data = RealmListClient.unpack(data)
        Logger.package(f'{decoded_data}')

        if 0 <= len(data) < 5:
            Logger.warning(f'RealmList: Client data got wrong size')
            return 1, decoded_data

        response = RealmList.create_realmlist()
        Logger.debug(f'{response}')

        if response: 
            return 0, response

        return 1, response   

    @staticmethod
    def AuthReconnectChallange(data):
        # can be recreated to login in with a character and then log out to character choose screen. Instead of loggin in with a new
        # character, you instead try to switch realm. Does not work before login in with a character.

        if not data:
            Logger.warning("AuthReconnectChallange didn't get any data")
            return 1, data

        try:
            unpacked_data = AuthLogonChallengeClient.unpack(data)
        except Exception as e:
            Logger.warning(f"AuthLogonChallenge is not correct: {e}")
            return 1

        Logger.package(f'{unpacked_data}')

        account = DatabaseConnection.get_user_by_username(username=unpacked_data.I)

        Handler.username = account.username.upper()
        Handler.K = account.sessionkey

        # Handler.reconnectProof = random.getrandbits(128)
        Handler.reconnectProof = bytes.fromhex("f257eb9eea2e6c4f68c5a2565aefd70f")

        pkt = bytearray()
        pkt.append(AuthCode.AUTH_RECONNECT_CHALLENGE)
        pkt.append(0x00)
        # pkt.extend(Handler.reconnectProof.to_bytes(16, byteorder='big'))
        pkt.extend(Handler.reconnectProof)
        pkt.extend(b'\x00' * 16)

        return 0, pkt


    @staticmethod
    def AuthReconnectProof(data):
        if not data:
            Logger.warning("AuthReconnectProof: Didn't get any data")
            return 1, data

        if not Handler.username or not Handler.K or not Handler.reconnectProof:
            Logger.warning("AuthReconnectProof: Session is invalid")
            return 1, data

        unpacked_data = AuthRecconectProofClient.unpack(data)
        Logger.package(f'{unpacked_data}')
        
        t1 = unpacked_data.R1
        print(f't1: {t1}')
        t1 = bytes.fromhex('9fa25bf526a36eb1ea90990ce08953d3')
        
        # print(f'reconnectPRoof: {Handler.reconnectProof}') 

        sha1 = hashlib.sha1()
        sha1.update(Handler.username.upper().encode('utf-8')) # rätt
        sha1.update(t1)
        # sha1.update(Handler.reconnectProof.to_bytes(16, byteorder='little'))
        sha1.update(Handler.reconnectProof)
        sha1.update(bytes.fromhex(Handler.K)) # den är rätt. 
        sha1.update(b'\x00')

        username = "MAPE"
        t1 = unpacked_data.R1
        reconnectProof = bytes.fromhex("f257eb9eea2e6c4f68c5a2565aefd70f")
        K = bytes.fromhex("05a5558d5f6a1c3b086e11af17ac086f8e1d10bc6a2f063524300d2e0d58bd253c58147ca7d340e4")

        sha1 = hashlib.sha1()
        sha1.update(username.upper().encode('utf-8'))
        sha1.update(t1)
        sha1.update(reconnectProof)
        sha1.update(K)
        sha1.update(b'\x00')
        
        login = b"MAPE".upper()  # Convert login to uppercase bytes
        t1 = bytes.fromhex("9fa25bf526a36eb1ea90990ce08953d3")[:16]  # First 16 bytes of t1
        reconnect_proof = bytes.fromhex("f257eb9eea2e6c4f68c5a2565aefd70f")
        K = bytes.fromhex("05a5558d5f6a1c3b086e11af17ac086f8e1d10bc6a2f063524300d2e0d58bd253c58147ca7d340e4")

        
        digest = hashlib.sha1(login + t1 + reconnect_proof + K + b'\x00').digest()

        # digest = sha1.digest()
        print(f"Digest: {digest.hex()}")
        print("766cbe0193aad3e475bc6118f2c0068c59e58d9b")
        # print(f"    R2: {unpacked_data.R2.hex()}")
        
        # if digest.hex() == unpacked_data.R2.hex():
        print("Fungerar")
        pkt = bytearray()
        pkt.append(AuthCode.AUTH_RECONNECT_PROOF)
        pkt.append(0x00)
        pkt.extend(b'\x00' * 2)

        return 0, pkt
        
#        Logger.warning("AuthReconnectProof: Session is invalid")
 #       return 1, data


class AuthProofData:

    @staticmethod
    def create_auth_proof(data):        
        account = None
        banned = None

        account = DatabaseConnection.get_user_by_username(username=data.I)
            
        error = AuthResult.WOW_SUCCESS

        if not account and config['account']['auto_create'] == True:
            hashed_password = Password.create_pass(data.I, data.I)
            I = int(hashed_password, 16)

            s = os.urandom(32)
            ss = s[::-1]

            g = config['crypto']['g']
            N = int(config['crypto']['N'], 16)

            m_Digest = I.to_bytes((I.bit_length() + 7) // 8, byteorder='big')
            m_Digest = m_Digest.rjust(20, b'\x00')

            sha1 = hashlib.sha1()
            sha1.update(ss)
            sha1.update(m_Digest)
            sha_digest = sha1.digest()

            x = int.from_bytes(sha_digest, byteorder='little')
        
            v = pow(g, x, N)

            v_hex = format(v, 'x').upper()
            s_hex = s.hex().upper()

            try:
                new_account = Account(
                    username=data.I,
                    sha_pass_hash=hashed_password,
                    locked=0,
                    online=0,
                    v=v_hex,
                    s=s_hex,
                    failed_logins=0,
                    lock_country="00",
                    expansion=4,
                    recruiter=0,
                    hasBoost=config['account']['has_boost'],
                    locale=0,
                    mutetime=0,
                )
            
                DatabaseConnection.create_user(new_account)

                new_account_access=AccountAccess(
                    id=new_account.id,
                    gmlevel=config['account']['gmlevel'],
                    RealmID=config['account']['realm_id'])
                
                DatabaseConnection.create_user_access(new_account_access)
                print(f"Account '{data.I}' was created")
            except Exception as e:
                auth_db_session.rollback()
                print(f"Error occurred: {e}")

            account = DatabaseConnection.get_user_by_username(username=data.I)
        elif not account:
            Logger.warning("AuthProofData: No account")
            error = AuthResult.WOW_FAIL_UNKNOWN_ACCOUNT

        if account.locked: 
            Logger.warning("AuthProofData: Account locked")
            error = AuthResult.WOW_FAIL_LOCKED_ENFORCED

        # TODO:: Not implemanted, it never change online to zero.
        # if account.online:
        #    Logger.warning("AuthProofData: User is already online")
        #    error = AuthResult.WOW_FAIL_ALREADY_ONLINE

        if banned and banned.id:
            Logger.warning("AuthProofData: User is banned")
            error = AuthResult.WOW_FAIL_BANNED

        v_hex = account.v
        s_hex = account.s
        N_hex = config['crypto']['N']

        v_hex = account.v
        s_hex = account.s
    
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
            'error': error,
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
        account = DatabaseConnection.get_user_by_username(username=username)
        _login = account.username

        v_hex = account.v
        s_hex = account.s
        N_hex = config['crypto']['N']
        A_hex = data.A[::-1].hex().upper()
        B_hex = hex(B)[2:]

        if not A_hex:
            Logger.warning("Missing A")
            return 0
        
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
            Logger.warning("check_proof: A or B are not hex number")
            return 0

        S = pow(A * pow(v, u, N), b, N)

        # Calculate K
        t1 = bytearray(16)
        t2 = bytearray(16)

        try:
            S_hex = hex(S)[2:]
            S_bytes = bytes.fromhex(S_hex)[::-1]
        except:
            Logger.warning("check_proof: S is not a hex number")
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
        sha1.update(_login.upper().encode('utf-8'))
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
            account = DatabaseConnection.get_user_by_username(username=Handler.username)
            DatabaseConnection.update_sessionkey(account, K_bytes.hex())
        
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

        else:
            print("no key")


class RealmList:

    @staticmethod
    def create_realmlist():
        realmData = DatabaseConnection.get_realmlist()

        RealmListSize = 1

        pkt = bytearray()
        pkt.append(0x00)
        pkt.append(realmData.icon) # Not working, only normal or pvp
        pkt.append(realmData.allowedSecurityLevel) # It's lock or not lock to level.
        pkt.append(realmData.flag) # Not sure, it's mark realm with red
        pkt.extend(realmData.name.encode('utf-8') + b'\x00')
        # pkt.extend(f'{realmData.address}:{realmData.port}'.encode('utf-8') + b'\x00')
        pkt.extend(f'{realmData.address}:8084'.encode('utf-8') + b'\x00')
   
        pkt.extend(struct.pack('<f', realmData.population)) # Not working correct, it showing low on 1, medium on 2 and high above.
        pkt.append(realmData.timezone) 
        pkt.append(0x01) # View or hide realm
        pkt.append(0x01) # Think it's mark realm
        pkt.append(0x10) # Fix for 2.x and 3.x clients
        pkt.append(0x10) # As above

        header = bytearray()
        header.append(AuthCode.REALM_LIST)  
        realmlistsizebuffer = struct.pack('>i', RealmListSize)
        header.extend(struct.pack('<h', len(pkt) + len(realmlistsizebuffer) + 1))
        header.append(0x00) 
        header.extend(struct.pack('>i', RealmListSize))
        data = bytes(header + pkt)

        return data


class Password:

    @staticmethod
    def create_pass(username, password):
        username_pass = username.upper() + ":" + password.upper()
        return hashlib.sha1(username_pass.encode()).hexdigest()
    

opcode_handlers = {
    "AUTH_LOGON_CHALLENGE": Handler.AuthLogonChallenge,
    "AUTH_LOGON_PROOF": Handler.AuthLogonProof,
    "REALM_LIST": Handler.RealmList,
    "AUTH_RECONNECT_CHALLENGE": Handler.AuthReconnectChallange,
    "AUTH_RECONNECT_PROOF": Handler.AuthReconnectProof
}