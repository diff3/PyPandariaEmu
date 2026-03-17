# modules/SRP6Session.py
# -*- coding: utf-8 -*-

from server.modules.crypto.SRP6Crypto import SRP6Crypto




class SRP6Session:
    """
    Minimal SRP6 server-side session.
    Stores username, salt, verifier
    and delegates math to SRP6Crypto().
    """

    def __init__(self, username: str, salt: bytes, verifier: bytes, mode: str | None = None):
        self.username = username
        self.salt = salt
        self.verifier = verifier

        # SRP6Crypto uses fixed N/g from internal constants
        self.core = SRP6Crypto(mode=mode)

        self.b_value = None
        self.B_bytes = None

    # ------------------------------------------------------------------
    # Backwards compatibility: both compute_B() and generate_B()
    # ------------------------------------------------------------------

    def compute_B(self):
        """Computes b and B — modern name."""
        self.b_value, self.B_bytes = self.core.server_make_B(self.verifier)
        return self.b_value, self.B_bytes

    def generate_B(self):
        """Legacy alias — old handlers expect this name."""
        self.compute_B()
        return self.B_bytes

    # ------------------------------------------------------------------

    def build_challenge(self) -> dict:
        """
        Creates b and B and returns dict fields for
        AUTH_LOGON_CHALLENGE_S.
        """

        # Generate b and B
        self.compute_B()

        # N (BE → LE)
        N_le = bytes.fromhex(self.core.N_HEX_BE)[::-1]

        return {
            "B": self.B_bytes,
            "g": self.core.G,
            "N": N_le,
            "s": self.salt,
        }

    # ------------------------------------------------------------------

    def verify_proof(self, A_bytes: bytes, M1_bytes: bytes):
        """
        Validates client proof M1.
        Returns (ok, M2, session_key)
        """

        ok, M2, k_bytes = self.core.server_verify(
            username=self.username,
            salt=self.salt,
            verifier=self.verifier,
            b_value=self.b_value,
            b_public=self.B_bytes,
            a_public=A_bytes,
            m1_client=M1_bytes,
        )

        if not ok:
            return False, None, None

        return True, M2, k_bytes
