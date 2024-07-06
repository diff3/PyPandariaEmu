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

        securityFlags = 0x00
        Logger.debug(f'flag= {securityFlags}')
        v = int(v_hex, 16)
        Logger.debug(f'v = {v}')
        N = int(N_hex, 16)
        Logger.debug(f'N = {N}')
     
        b = random.getrandbits(152)
        Logger.debug(f'b = {b}')
        g = config['crypto']['g']
        Logger.debug(f'g = {g}')

        gmod = pow(g, b, N)
        B = ((v * 3) + gmod) % N
        Logger.debug(f'B = {B}')

        s_bytes = bytes.fromhex(s_hex)
        Logger.debug(f's_bytes = {s_bytes}')
        unk3 = random.getrandbits(128)
        Logger.debug(f'unk3 = {unk3}')

        pkt = bytearray()
        pkt.append(AUTH_LOGON_CHALLENGE)
        pkt.append(0x00)
        pkt.append(WOW_SUCCESS)
        pkt.extend(B.to_bytes(32, byteorder='big'))
        pkt.append(1)
        pkt.append(g)
        pkt.append(32)
        pkt.extend(N.to_bytes(32, byteorder='big'))
        pkt.extend(s_bytes)
        pkt.extend(unk3.to_bytes(16, byteorder='big'))
        pkt.append(securityFlags)

        return pkt, b, B


class Password:

    @staticmethod
    def create_pass(username, password):
        username_pass = username.upper() + ":" + password.upper()
        return hashlib.sha1(username_pass.encode()).hexdigest().upper()