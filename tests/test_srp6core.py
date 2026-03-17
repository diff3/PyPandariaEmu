import unittest
import os
from protocols.wow.shared.modules.crypto.SRP6Crypto import SRP6Crypto


class TestSRP6Crypto(unittest.TestCase):
    """Unit tests for the SRP6Crypto class (SkyFire SRP6 implementation)."""

    def setUp(self) -> None:
        """Create a fresh SRP6Crypto instance for each test."""
        self.core = SRP6Crypto()
        self.username = "srptest"
        self.password = "srptest"

    # -------------------------------------------------------------
    # Salt & Verifier generation
    # -------------------------------------------------------------

    def test_generate_salt_length(self) -> None:
        """Ensures generated salt is always 32 bytes."""
        salt = self.core.generate_salt()
        self.assertEqual(len(salt), 32)

    def test_calculate_verifier_deterministic(self) -> None:
        """Same username, password and salt must generate identical verifiers."""
        salt = self.core.generate_salt()

        v1 = self.core.calculate_verifier(self.username, self.password, salt)
        v2 = self.core.calculate_verifier(self.username, self.password, salt)

        self.assertEqual(v1, v2)

    # -------------------------------------------------------------
    # Password checking
    # -------------------------------------------------------------

    def test_check_password_success(self) -> None:
        """Valid username and password must match the stored verifier."""
        salt = self.core.generate_salt()
        verifier = self.core.calculate_verifier(self.username, self.password, salt)

        result = self.core.check_password(self.username, self.password, salt, verifier)
        self.assertTrue(result)

    def test_check_password_failure(self) -> None:
        """Wrong password must fail validation."""
        salt = self.core.generate_salt()
        verifier = self.core.calculate_verifier(self.username, self.password, salt)

        result = self.core.check_password(self.username, "incorrect", salt, verifier)
        self.assertFalse(result)

    # -------------------------------------------------------------
    # Server B generation
    # -------------------------------------------------------------

    def test_server_make_B_returns_valid_tuple(self) -> None:
        """server_make_B() must return (b:int, B:bytes) where B is 32 bytes."""
        salt = self.core.generate_salt()
        verifier = self.core.calculate_verifier(self.username, self.password, salt)

        b_value, B_bytes = self.core.server_make_B(verifier)

        self.assertIsInstance(b_value, int)
        self.assertEqual(len(B_bytes), 32)

    # -------------------------------------------------------------
    # Full server-side verification: A + M1
    # -------------------------------------------------------------

    def test_full_handshake_success(self) -> None:
        """Full simulated handshake must return (True, M2)."""

        # Prepare account
        salt = self.core.generate_salt()
        verifier = self.core.calculate_verifier(self.username, self.password, salt)
        username_u = self.core.upper_skyfire(self.username)

        # CLIENT: Generate a + A
        a_value = int.from_bytes(os.urandom(32), "little")
        A_int = pow(self.core.G, a_value, self.core._modulus_int)
        A_bytes = self.core.int_to_32_le(A_int)

        # SERVER: Generate b + B
        b_value, B_bytes = self.core.server_make_B(verifier)

        # Compute u
        u_value = self.core.compute_u(A_bytes, B_bytes)

        # CLIENT: compute x
        up_hash = self.core.sha1(f"{username_u}:{username_u}".encode("utf-8"))
        x_value = self.core.sha1_to_int_le(salt, up_hash)

        # CLIENT: compute S
        g_x = pow(self.core.G, x_value, self.core._modulus_int)
        base_client = (int.from_bytes(B_bytes, "little") - 3 * g_x) % self.core._modulus_int
        exp_client = a_value + u_value * x_value

        S_client_int = pow(base_client, exp_client, self.core._modulus_int)
        S_client_bytes = self.core.int_to_32_le(S_client_int)

        K_client = self.core.sha1_interleave(S_client_bytes)
        M1_client = self.core.compute_M1(username_u, salt, A_bytes, B_bytes, K_client)

        # SERVER VERIFY
        ok, M2_server, _ = self.core.server_verify(
            username=self.username,
            salt=salt,
            verifier=verifier,
            b_value=b_value,
            b_public=B_bytes,
            a_public=A_bytes,
            m1_client=M1_client,
        )

        self.assertTrue(ok)
        self.assertIsNotNone(M2_server)
        self.assertEqual(len(M2_server), 20)

    def test_full_handshake_failure(self) -> None:
        """Server must fail verification if M1 is modified."""

        # Prepare account
        salt = self.core.generate_salt()
        verifier = self.core.calculate_verifier(self.username, self.password, salt)

        # Fake values for simplicity
        bad_A = os.urandom(32)
        bad_M1 = os.urandom(20)
        b_value, B_bytes = self.core.server_make_B(verifier)

        ok, M2_server, _ = self.core.server_verify(
            username=self.username,
            salt=salt,
            verifier=verifier,
            b_value=b_value,
            b_public=B_bytes,
            a_public=bad_A,
            m1_client=bad_M1,
        )

        self.assertFalse(ok)
        self.assertIsNone(M2_server)


if __name__ == "__main__":
    unittest.main()
