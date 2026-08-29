import hashlib
import secrets


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000).hex()


def generate_reset_token():
    return secrets.token_hex(16)


def main():
    salt = secrets.token_bytes(16)
    print(hash_password("s3cret", salt))


if __name__ == "__main__":
    main()
