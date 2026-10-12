import unittest

from hashing import BCRYPT_MAX_BYTES, bcrypt_hash, bcrypt_verify, compare, sha256_hash
from main import check

# Low cost factor keeps the tests fast; the behaviour being tested is the same.
FAST_ROUNDS = 4


class Sha256Tests(unittest.TestCase):
    def test_same_password_gives_same_hash(self):
        self.assertEqual(sha256_hash("hunter2"), sha256_hash("hunter2"))

    def test_known_value(self):
        self.assertEqual(
            sha256_hash("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )


class BcryptTests(unittest.TestCase):
    def test_same_password_gives_different_hashes(self):
        self.assertNotEqual(
            bcrypt_hash("hunter2", rounds=FAST_ROUNDS),
            bcrypt_hash("hunter2", rounds=FAST_ROUNDS),
        )

    def test_hash_records_cost_factor(self):
        self.assertTrue(bcrypt_hash("hunter2", rounds=FAST_ROUNDS).startswith("$2b$04$"))

    def test_verify_accepts_right_and_rejects_wrong_password(self):
        stored = bcrypt_hash("hunter2", rounds=FAST_ROUNDS)
        self.assertTrue(bcrypt_verify("hunter2", stored))
        self.assertFalse(bcrypt_verify("hunter3", stored))

    def test_rejects_passwords_over_72_bytes(self):
        with self.assertRaises(ValueError):
            compare("x" * (BCRYPT_MAX_BYTES + 1))


class ReportTests(unittest.TestCase):
    def test_report_never_contains_the_password(self):
        password = "T7#qL9!vX2@mR4&z"
        self.assertNotIn(password, check(password))

    def test_report_handles_overlong_password(self):
        self.assertIn("Hash demo skipped", check("x" * 80))


if __name__ == "__main__":
    unittest.main()
