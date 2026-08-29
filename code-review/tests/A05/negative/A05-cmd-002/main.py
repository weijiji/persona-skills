import subprocess


def ping_host(host):
    subprocess.run(["ping", host])


def main():
    host = input("host: ")
    ping_host(host)


if __name__ == "__main__":
    main()
