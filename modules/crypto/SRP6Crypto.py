#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from shared.ConfigLoader import ConfigLoader

import hashlib
import os

cfg = ConfigLoader.load_config()
crypto = cfg["crypto"]

class SRP6Crypto:
    """
    Implements the SRP-6 authentication protocol used by
    World of Warcraft (SkyFire / MoP era). This class isolates
    all SRP-related math and hashing, with correct SkyFire-specific
    byte ordering and ASCII uppercase rules.

    The class provides:
        * Salt + verifier generation
        * Server-side B generation
        * Server-side verification of A + M1
        * Session proof M2 generation
        * Utility method to create MariaDB INSERT statements.
    """

    # N in big-endian hex from SkyFire source
    N_HEX_BE: str = crypto["N"]
    G: int = int(crypto["g"])

    def __init__(self, mode: str | None = None) -> None:
        """Initialize SRP-6 core parameters."""
        self.mode = mode
        _config = None  # placeholder so you can keep pattern

        # In C++ de gör de ungefär:
        #   N.SetHexStr("894B...");
        #   N.ToByteArray<32>(buf, true)  // little-endian
        modulus_bytes_be = bytes.fromhex(self.N_HEX_BE)
        self._modulus_bytes_be = modulus_bytes_be          # big-endian form
        self._modulus_bytes_le = modulus_bytes_be[::-1]    # little-endian bytes (SkyFire-style)

        # Numeriskt värde – samma oavsett om vi tolkar BE eller LE korrekt
        self._modulus_int = int.from_bytes(self._modulus_bytes_le, "little")

    def get_N_bytes(self) -> bytes:
        """Return modulus N as little-endian bytes."""
        return self._modulus_bytes_le

    # ======================================================================
    # Utility: ASCII-only uppercase (SkyFire Utf8ToUpperOnlyLatin)
    # ======================================================================

    def upper_skyfire(self, text: str) -> str:
        """
        Converts ASCII characters a–z to uppercase while leaving
        all non-basic-latin characters untouched.
        """
        _config = None

        result = []
        for char in text:
            code = ord(char)
            if 0 <= code <= 0x7F:
                if 0x61 <= code <= 0x7A:  # 'a'–'z'
                    result.append(chr(code - 0x20))
                else:
                    result.append(char)
            else:
                result.append(char)
        return "".join(result)


    def compute_world_auth_digest(
        self,
        account: str,
        client_seed_bytes: bytes,
        server_seed_bytes: bytes,
        session_key_bytes: bytes,
    ) -> bytes:
        """
        SkyFire CMSG_AUTH_SESSION digest:

        SHA1(
            UPPER(account) +
            4x 0x00 +
            clientSeed (4 bytes LE) +
            serverSeed (4 bytes LE) +
            sessionKey (40 bytes)
        )
        """

        if len(client_seed_bytes) != 4:
            raise ValueError("client_seed_bytes must be 4 bytes")
        if len(server_seed_bytes) != 4:
            raise ValueError("server_seed_bytes must be 4 bytes")
        if len(session_key_bytes) != 40:
            raise ValueError("session_key_bytes must be 40 bytes")

        acct_up = self.upper_skyfire(account)

        return self.sha1(
            acct_up.encode("latin-1"),
            b"\x00\x00\x00\x00",
            client_seed_bytes,
            server_seed_bytes,
            session_key_bytes,
        )
    

    # ======================================================================
    # Hash helpers
    # ======================================================================

    def sha1(self, *parts: bytes) -> bytes:
        """
        Computes SHA-1 over concatenated byte sequences.

        Returns:
            bytes: SHA-1 digest (20 bytes).
        """
        _config = None

        sha = hashlib.sha1()
        for part in parts:
            if isinstance(part, int):
                raise TypeError("sha1(): pass ints as bytes explicitly")
            sha.update(part)
        return sha.digest()

    def sha1_to_int_le(self, *parts: bytes) -> int:
        """
        Computes SHA-1 and interprets the digest as a little-endian integer.

        Detta motsvarar BigNumber(SetBinary(..., littleEndian=true))
        i SkyFire-koden.
        """
        digest = self.sha1(*parts)
        return int.from_bytes(digest, "little")

    @staticmethod
    def int_to_32_le(value: int) -> bytes:
        """
        Convert integer into 32 bytes little-endian.
        WoW uses fixed 32-byte SRP fields.
        """
        return value.to_bytes(32, "little")

    # ======================================================================
    # SHA1 interleave (SkyFire session key algorithm)
    # ======================================================================

    def sha1_interleave(self, s_bytes: bytes) -> bytes:
        """
        Compute the SRP session key using SkyFire-style SHA1Interleave.

        Args:
            s_bytes (bytes): 32-byte SRP shared secret S (little-endian).

        Returns:
            bytes: 40-byte interleaved session key K.
        """
        _config = None

        if len(s_bytes) != 32:
            raise ValueError("S must be 32 bytes")

        # SkyFire: buf0 = S[0],S[2],..., buf1 = S[1],S[3],...
        buf0 = s_bytes[0::2]
        buf1 = s_bytes[1::2]

        # Find first non-zero in full S
        p = 0
        while p < len(s_bytes) and s_bytes[p] == 0:
            p += 1
        if p & 1:
            p += 1
        p //= 2  # offset into buf0 / buf1

        h0 = hashlib.sha1(buf0[p:]).digest()
        h1 = hashlib.sha1(buf1[p:]).digest()

        out = bytearray(40)
        for i in range(20):
            out[2 * i] = h0[i]
            out[2 * i + 1] = h1[i]

        return bytes(out)

    # ======================================================================
    # Account generation
    # ======================================================================

    @staticmethod
    def generate_salt() -> bytes:
        """Return a cryptographically secure 32-byte salt."""
        _config = None
        return os.urandom(32)

    def calculate_verifier(self, username: str, password: str, salt: bytes) -> bytes:
        """
        Create the SRP verifier v = g^x mod N.

        Args:
            username (str): Username (SkyFire ASCII uppercase applied).
            password (str): Password (SkyFire ASCII uppercase applied).
            salt (bytes): 32-byte random salt.

        Returns:
            bytes: 32-byte little-endian verifier.
        """
        _config = None

        username_u = self.upper_skyfire(username)
        password_u = self.upper_skyfire(password)

        up_hash = self.sha1(f"{username_u}:{password_u}".encode("utf-8"))
        x = self.sha1_to_int_le(salt, up_hash)
        verifier_int = pow(self.G, x, self._modulus_int)

        return self.int_to_32_le(verifier_int)

    def calculate_verifier_from_hash(self, sha_pass_hash: str | bytes, salt: bytes) -> bytes:
        """
        Create SRP verifier using a precomputed SHA1(USER:PASS) hash.
        """
        if isinstance(sha_pass_hash, str):
            hash_bytes = bytes.fromhex(sha_pass_hash.strip())
        else:
            hash_bytes = bytes(sha_pass_hash)

        x = self.sha1_to_int_le(salt, hash_bytes)
        verifier_int = pow(self.G, x, self._modulus_int)
        return self.int_to_32_le(verifier_int)

    def check_password(
        self,
        username: str,
        password: str,
        salt: bytes,
        verifier: bytes,
    ) -> bool:
        """
        Verify that username+password produces the expected verifier.

        Returns:
            bool: True if the verifier matches, False otherwise.
        """
        _config = None

        expected = self.calculate_verifier(username, password, salt)
        return expected == verifier

    # ======================================================================
    # Server-side B generation
    # ======================================================================

    def server_make_b_value(self) -> int:
        """
        Generate a random 32-byte private value b.

        Returns:
            int: Private server exponent b.
        """
        _config = None

        # klientkod i din test använder också 32-byte little-endian slump
        return int.from_bytes(os.urandom(32), "little")

    def server_make_B(self, verifier_le: bytes) -> tuple[int, bytes]:
        """
        Compute server public value B = g^b + 3*v mod N.

        verifier_le:
            32-byte *little-endian* verifier (samma format som i din accounts-dict
            och som din testkod genererar).
        """
        _config = None

        if len(verifier_le) != 32:
            raise ValueError("Verifier must be 32 bytes (little-endian)")

        # convert verifier to int (little-endian, SkyFire-style)
        v_int = int.from_bytes(verifier_le, "little")

        # random b
        b_value = self.server_make_b_value()

        # compute B
        B_int = (pow(self.G, b_value, self._modulus_int) + 3 * v_int) % self._modulus_int

        # send B as 32-byte little-endian
        B_bytes = self.int_to_32_le(B_int)

        return b_value, B_bytes

    # ======================================================================
    # Handshake math: u, S, K
    # ======================================================================

    def compute_u(self, a_bytes: bytes, b_bytes: bytes) -> int:
        """
        Compute the SRP scrambling parameter u = H(A | B) as little-endian int.
        """
        _config = None
        return self.sha1_to_int_le(a_bytes, b_bytes)

    def server_compute_S(
        self,
        a_public: bytes,
        verifier_le: bytes,
        b_value: int,
        u_value: int,
    ) -> bytes:
        """
        Compute server shared secret S = (A * v^u)^b mod N.

        Args:
            a_public (bytes): Client A, 32-byte little-endian.
            verifier_le (bytes): 32-byte little-endian verifier v.
            b_value (int): Server private exponent b.
            u_value (int): Scrambler u.

        Returns:
            bytes: 32-byte little-endian S.
        """
        _config = None

        if len(a_public) != 32:
            raise ValueError("A must be 32 bytes")
        if len(verifier_le) != 32:
            raise ValueError("Verifier must be 32 bytes")

        # OBS: little-endian to int – matchar din testkod
        a_int = int.from_bytes(a_public, "little")
        v_int = int.from_bytes(verifier_le, "little")

        base = (a_int * pow(v_int, u_value, self._modulus_int)) % self._modulus_int
        s_int = pow(base, b_value, self._modulus_int)
        return self.int_to_32_le(s_int)

    def server_compute_K(self, s_bytes_32: bytes) -> bytes:
        """
        Compute the final 40-byte session key K.
        """
        _config = None
        return self.sha1_interleave(s_bytes_32)

    # ======================================================================
    # Proof values M1 and M2
    # ======================================================================

    def compute_M1(
        self,
        username_u: str,
        salt: bytes,
        a_bytes: bytes,
        b_bytes: bytes,
        k_bytes: bytes,
    ) -> bytes:
        """
        Compute the client/server shared proof M1.

        M1 = H( H(N) xor H(g), H(I), s, A, B, K )

        Här används:
          - H(N) över little-endian N-bytes (matchar din testkod)
          - g som ett bytevärde (0x07)
          - I = uppercased username
        """
        _config = None

        # H(N) over little-endian N bytes (som i din srp6.py)
        hash_n = self.sha1(self._modulus_bytes_le)
        hash_g = self.sha1(bytes([self.G]))
        xor_ng = bytes(x ^ y for x, y in zip(hash_n, hash_g))

        hash_i = self.sha1(username_u.encode("utf-8"))

        return self.sha1(xor_ng, hash_i, salt, a_bytes, b_bytes, k_bytes)

    def compute_M2(self, a_bytes: bytes, m1_bytes: bytes, k_bytes: bytes) -> bytes:
        """
        Compute the server's final session proof M2 = H(A, M1, K).
        """
        _config = None
        return self.sha1(a_bytes, m1_bytes, k_bytes)

    # ======================================================================
    # Full server verification (A + M1)
    # ======================================================================

    def server_verify(
        self,
        username: str,
        salt: bytes,
        verifier: bytes,
        b_value: int,
        b_public: bytes,
        a_public: bytes,
        m1_client: bytes,
    ) -> tuple[bool, bytes | None, bytes | None]:
        """
        Perform full server-side verification of the client's A + M1.

        Returns:
            (True, M2_bytes, K_bytes) on success, (False, None, None) on failure.
        """
        _config = None

        username_u = self.upper_skyfire(username)

        # --- compute u -------------------------------------------------
        u_value = self.compute_u(a_public, b_public)

        # --- compute S -------------------------------------------------
        s_bytes = self.server_compute_S(a_public, verifier, b_value, u_value)

        # --- compute K -------------------------------------------------
        k_bytes = self.server_compute_K(s_bytes)

        # --- compute M1 ------------------------------------------------
        m1_server = self.compute_M1(username_u, salt, a_public, b_public, k_bytes)

        if m1_server != m1_client:
            return False, None, None

        # --- compute M2 ------------------------------------------------
        m2 = self.compute_M2(a_public, m1_client, k_bytes)

        return True, m2, k_bytes

    # ======================================================================
    # High-level: Generate salt + verifier (SkyFire MakeRegistrationData)
    # ======================================================================

    def make_registration(self, username: str, password: str) -> tuple[bytes, bytes]:
        """
        High-level helper (SkyFire::SRP6::MakeRegistrationData):
        Generate 32-byte salt + 32-byte verifier from username/password.

        Returns:
            (salt_bytes, verifier_bytes)
        """
        username_u = self.upper_skyfire(username)
        password_u = self.upper_skyfire(password)

        salt = self.generate_salt()
        verifier = self.calculate_verifier(username_u, password_u, salt)

        return salt, verifier
