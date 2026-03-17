#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib


class ShaPassHash:
    """
    Implements the legacy World of Warcraft account hash used by
    pre-SRP6 authentication systems (e.g. MaNGOS, TrinityCore, many older
    MoP/TBC/LK forks).

    This algorithm is *not* SRP6. It does not use salts, verifiers, or any
    challenge/response math. It simply hashes:

        SHA1( UPPERCASE(username) + ":" + UPPERCASE(password) )

    Use this when dealing with legacy cores that expect the `sha_pass_hash`
    style password field rather than SRP6's (salt, verifier).
    """

    @staticmethod
    def generate(username: str, password: str) -> str:
        """
        Compute SHA1(USERNAME:PASSWORD) in uppercase ASCII.

        Returns:
            Uppercase hex digest, matching all known implementations.
        """
        data = f"{username.upper()}:{password.upper()}"
        return hashlib.sha1(data.encode("utf-8")).hexdigest().upper()

    @staticmethod
    def verify(username: str, password: str, stored_hash: str) -> bool:
        """
        Validate a cleartext password against an existing legacy hash.
        """
        return ShaPassHash.generate(username, password) == stored_hash.upper()