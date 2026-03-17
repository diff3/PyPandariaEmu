#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import socket
from typing import Dict

from DSL.modules.dsl.EncoderHandler import EncoderHandler
from server.modules.crypto.SRP6Client import H, SRP6Client


class AuthClientBuilder:
    @staticmethod
    def build_logon_challenge(username: str, client_cfg: Dict) -> bytes:
        user = username.upper()
        size = AuthClientBuilder._challenge_size(len(user))

        fields = {
            "cmd": 0x00,
            "error": 0x08,
            "size": size,
            "gamename": AuthClientBuilder._reverse_for_encode("WoW"),
            "version1": 5,
            "version2": 4,
            "version3": 8,
            "build": client_cfg["build"],
            "platform": AuthClientBuilder._reverse_for_encode(client_cfg["platform"]),
            "os": AuthClientBuilder._reverse_for_encode(client_cfg["os"]),
            "country": AuthClientBuilder._reverse_for_encode(client_cfg["country"]),
            "timezone_bias": client_cfg["timezone"],
            "ip": socket.inet_aton(client_cfg["ip"]),
            "I_len": len(user),
            "username": user,
        }

        return EncoderHandler.encode_packet("AUTH_LOGON_CHALLENGE_C", fields)

    @staticmethod
    def build_logon_proof(srp: SRP6Client) -> bytes:
        fields = {
            "cmd": 0x01,
            "A": srp.A_wire,
            "M1": srp.M1,
            "crc_hash": H(srp.A_wire, srp.M1, srp.K),
            "number_of_keys": 0,
            "security_flags": 0,
        }
        return EncoderHandler.encode_packet("AUTH_LOGON_PROOF_C", fields)

    @staticmethod
    def build_realm_list(build: int) -> bytes:
        fields = {
            "cmd": 0x10,
            "build": build,
        }
        return EncoderHandler.encode_packet("REALM_LIST_C", fields)

    @staticmethod
    def _challenge_size(username_len: int) -> int:
        return 30 + username_len

    @staticmethod
    def _reverse_for_encode(value: str) -> str:
        return value[::-1]
