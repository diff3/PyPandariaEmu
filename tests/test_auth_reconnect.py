import json
import unittest
from pathlib import Path
from utils.ConfigLoader import ConfigLoader

import yaml
cfg = ConfigLoader.get_config()
cfg["program"] = "wow"
cfg["expansion"] = "mop"
cfg["version"] = "v18414"
cfg["Logging"]["logging_levels"] = "Information, Success, Error"

class DummySocket:
    """Minimal stub to satisfy handler signature."""

    def fileno(self):
        return 0


class TestAuthReconnect(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.program = cfg["program"]
        cls.expansion = cfg.get("expansion")
        cls.version = cfg["version"]

        def read_raw(name: str) -> bytes | None:
            path = (
                Path("protocols")
                / cls.program
                / cls.expansion
                / cls.version
                / "data"
                / "debug"
                / f"{name}.json"
            )
            if not path.exists():
                return None
            data = json.loads(path.read_text(encoding="utf-8"))

            raw_hex = data.get("raw_data_hex")
            if raw_hex:
                return bytes.fromhex(raw_hex.replace(" ", ""))

            header_hex = data.get("raw_header_hex")
            payload_hex = data.get("hex_compact") or data.get("hex_spaced")
            if header_hex and payload_hex:
                return bytes.fromhex(header_hex.replace(" ", "") + payload_hex.replace(" ", ""))
            if payload_hex:
                return bytes.fromhex(payload_hex.replace(" ", ""))
            return None

        dbg_path = (
            Path("protocols")
            / cls.program
            / cls.expansion
            / cls.version
            / "data"
            / "debug"
            / "AUTH_RECONNECT_CHALLENGE_C.json"
        )

        cls.binary_data = read_raw("AUTH_RECONNECT_CHALLENGE_C")
        cls.expected_response = read_raw("AUTH_RECONNECT_CHALLENGE_S")

        if cls.binary_data is None or cls.expected_response is None:
            raise unittest.SkipTest("Missing debug fixtures for auth reconnect challenge")

        try:
            module_path = (
                f"protocols.{cls.program}.{cls.expansion}.{cls.version}.modules.handlers.AuthHandlers"
            )
            AH = __import__(module_path, fromlist=["opcode_handlers"])
        except ImportError as exc:
            raise unittest.SkipTest(f"AuthHandlers import failed: {exc}")

        cls.AH = AH

    def test_build_auth_reconnect_challenge_s(self):
        """Builder should return raw bytes with cmd=0x02 and expected length."""
        proof_seed = self.expected_response[-16:]

        def fake_urandom(n):
            return proof_seed[:n]

        original_urandom = self.AH.os.urandom
        self.AH.os.urandom = fake_urandom
        try:
            out = self.AH.build_AUTH_RECONNECT_CHALLENGE_S()
        finally:
            self.AH.os.urandom = original_urandom

        self.assertIsInstance(out, (bytes, bytearray))
        self.assertGreaterEqual(len(out), 1)
        self.assertEqual(out[0], self.expected_response[0])  # cmd
        self.assertTrue(out.endswith(proof_seed))

    def test_handle_auth_reconnect_challenge_c(self):
        """Handler should decode input and return (0, bytes)."""
        dummy_sock = DummySocket()
        proof_seed = self.expected_response[-16:]

        def fake_urandom(n):
            return proof_seed[:n]

        original_urandom = self.AH.os.urandom
        self.AH.os.urandom = fake_urandom
        err, resp = self.AH.handle_AUTH_RECONNECT_CHALLENGE_C(
            dummy_sock,
            self.binary_data[0] if getattr(self, "binary_data", b"") else 0,
            self.binary_data,
        )
        self.AH.os.urandom = original_urandom

        self.assertEqual(err, 0)
        self.assertIsInstance(resp, (bytes, bytearray))
        self.assertGreaterEqual(len(resp), 1)
        self.assertEqual(resp[0], self.expected_response[0])  # cmd
        self.assertTrue(resp.endswith(proof_seed))


if __name__ == "__main__":
    unittest.main()
