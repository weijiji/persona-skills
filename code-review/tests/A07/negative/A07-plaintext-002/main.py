import hashlib


def verify_password(stored_hash: bytes, password: str, salt: bytes) -> bool:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return digest == stored_hash


if __name__ == "__main__":
    import sys
    verify_password(b"", sys.argv[1].encode(), b"")
