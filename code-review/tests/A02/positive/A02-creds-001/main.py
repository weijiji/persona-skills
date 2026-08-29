ADMIN_USER, ADMIN_PASSWORD = "admin", "admin123"


def authenticate(username, password):
    if username == ADMIN_USER and password == ADMIN_PASSWORD:
        return True
    return False


def main():
    if authenticate("admin", "admin123"):
        print("logged in")


if __name__ == "__main__":
    main()
