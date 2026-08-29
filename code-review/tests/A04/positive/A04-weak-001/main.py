import hashlib


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def store_password(username, password):
    digest = hash_password(password)
    save_to_db(username, digest)

def save_to_db(username, digest):
    print(f"{username}: {digest}")

def main():
    store_password("alice", "s3cret")

if __name__ == "__main__":
    main()
