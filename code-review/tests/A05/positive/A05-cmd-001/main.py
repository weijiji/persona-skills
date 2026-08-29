import os


def ping_host(host):
    os.system("ping " + host)


def main():
    host = input("host: ")
    ping_host(host)


if __name__ == "__main__":
    main()
