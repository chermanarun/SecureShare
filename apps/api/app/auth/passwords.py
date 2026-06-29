import base64
import hashlib
import hmac
import os


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 390_000)
    return "pbkdf2_sha256$390000$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_b64, digest_b64 = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


_DUMMY_HASH = "pbkdf2_sha256$390000$AAAAAAAAAAAAAAAAAAAAAA==$8pAxa8L4K9TXLrJQWorQkVOnvqk0G5fvlyxP+6A6j48="


def verify_password_or_dummy(password: str, encoded: str | None) -> bool:
    return verify_password(password, encoded or _DUMMY_HASH)
