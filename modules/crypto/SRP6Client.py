#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SRP6Client – Pure client-side SRP-6a mathematics for World of Warcraft authentication.

Purpose
-------
This module implements the client calculations for the SRP-6a protocol used by
WoW's authentication handshake (MoP/SkyFire style). Unlike server-side SRP6Crypto,
this class NEVER
reads N or g from configuration. Those values must come directly from the
server's AUTH_LOGON_CHALLENGE_S packet.

The class provides:
    * A calculation of A (client public value)
    * Derivation of shared session key K
    * Calculation of client proof M1

Why?
----
This file documents the SRP process from the *client perspective* and is
valuable for research, testing, automation and replay tools. It works together
with the packet DSL decoders/encoders, but does not build packets itself.

Scope
-----
This client implementation matches MoP/SkyFire SRP behavior (little-endian,
trimmed SHA1 interleave). Vanilla/vMangos uses a different interleave and
storage conventions; do not use this class for v1.12.1 flows.

Coding Standards
----------------
- PEP8 formatting
- NASA-style clarity: no magic numbers, explicit logic
- Full type annotations
- Clear error handling and no silent failures
"""

import os
import hashlib


def H(*values: bytes) -> bytes:
    """SHA-1 helper used across SRP computations."""
    h = hashlib.sha1()
    for v in values:
        h.update(v)
    return h.digest()


def sha1_interleave(S: bytes) -> bytes:
    """
    Performs Blizzard-style SHA1 interleave on 32-byte S.

    Args:
        S (bytes): 32-byte SRP shared secret.

    Returns:
        bytes: 40-byte interleaved session key K.
    """
    S0 = S[0::2]
    S1 = S[1::2]

    h0 = hashlib.sha1(S0).digest()
    h1 = hashlib.sha1(S1).digest()

    out = bytearray(40)
    for i in range(20):
        out[2 * i] = h0[i]
        out[2 * i + 1] = h1[i]
    return bytes(out)


class SRP6Client:
    """
    Implements the client-side SRP-6a math for WoW.

    Notes
    -----
    - Server sends (g, N, B, s) inside AUTH_LOGON_CHALLENGE_S.
    - Client MUST use those exact values (never config values).
    - All math here is protocol-correct and endian-safe.

    Responsibilities
    ----------------
    * Compute A = g^a mod N
    * Compute shared secret S
    * Compute session key K (40 bytes)
    * Compute M1 proof sent to server
    """

    def __init__(self, username: str, password: str) -> None:
        """
        Initialize the SRP client with username and password.

        Args:
            username (str): Account username.
            password (str): Account password.
        """
        # Global config pattern placeholder (NASA rule #5)
        _config = None

        self.I_str = username.upper()
        self.P_str = password.upper()

        self.I = self.I_str.encode("ascii")
        self.P = self.P_str.encode("ascii")

        # Client secret exponent (private key)
        self.a_int = int.from_bytes(os.urandom(32), "little")

        # Will be filled after server challenge arrives
        self.A_int = None
        self.A_wire = None
        self.B_wire = None
        self.B_int = None
        self.N_int = None
        self.N_wire = None
        self.g = None
        self.salt = None

        self.K = None
        self.M1 = None

    # ------------------------------------------------------------------
    def load_challenge(
        self,
        B_wire: bytes,
        g: int,
        N_wire: bytes,
        salt: bytes,
    ) -> None:
        """
        Load SRP parameters sent from the server.

        Args:
            B_wire (bytes): Server public value B (32 bytes).
            g (int): Generator value.
            N_wire (bytes): Modulus N (32 bytes, little-endian wire format).
            salt (bytes): User SRP salt (32 bytes).
        """
        # Global config pattern placeholder
        _config = None

        self.B_wire = B_wire
        self.g = g
        self.salt = salt
        self.N_wire = N_wire

        self.B_int = int.from_bytes(B_wire, "little")
        self.N_int = int.from_bytes(N_wire, "little")

    # ------------------------------------------------------------------
    def compute_A(self) -> bytes:
        """
        Compute client public value A = g^a mod N.

        Returns:
            bytes: A encoded as 32-byte little-endian wire format.
        """
        _config = None

        A_int = pow(self.g, self.a_int, self.N_int)
        self.A_int = A_int
        self.A_wire = A_int.to_bytes(32, "little")
        return self.A_wire

    # ------------------------------------------------------------------
    def compute_shared_key(self) -> bytes:
        """
        Derive shared SRP secret S and session key K.

        Returns:
            bytes: Session key K (40 bytes).
        """
        _config = None

        if self.A_wire is None or self.B_wire is None:
            raise ValueError("SRP6Client: Missing A or B for computation")

        u = int.from_bytes(H(self.A_wire, self.B_wire), "little")

        # x = SHA1(s || SHA1(I:P))
        up_hash = hashlib.sha1(f"{self.I_str}:{self.P_str}".encode("ascii")).digest()
        x = int.from_bytes(hashlib.sha1(self.salt + up_hash).digest(), "little")

        v = pow(self.g, x, self.N_int)

        # g^b = (B - 3*v) mod N
        three_v = ((v << 1) + v) % self.N_int
        g_b = (self.B_int - three_v) % self.N_int

        exponent = self.a_int + u * x

        S = pow(g_b, exponent, self.N_int)
        self.K = sha1_interleave(S.to_bytes(32, "little"))

        return self.K

    # ------------------------------------------------------------------
    def compute_M1(self) -> bytes:
        """
        Compute client proof value M1.

        Returns:
            bytes: 20-byte SHA1 proof.
        """
        _config = None

        HN = H(self.N_wire)
        Hg = H(bytes([self.g]))
        NgXor = bytes(a ^ b for a, b in zip(HN, Hg))

        H_I = H(self.I)

        self.M1 = H(NgXor, H_I, self.salt, self.A_wire, self.B_wire, self.K)
        return self.M1
