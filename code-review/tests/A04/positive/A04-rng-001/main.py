import random


def generate_reset_token():
    return str(random.randint(100000, 999999))


def main():
    token = generate_reset_token()
    print(f"reset token: {token}")


if __name__ == "__main__":
    main()
