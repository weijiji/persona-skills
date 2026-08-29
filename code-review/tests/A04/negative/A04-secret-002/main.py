import os
import requests

API_KEY = os.environ["API_KEY"]


def call_payment_api(amount):
    headers = {"Authorization": f"Bearer {API_KEY}"}
    return requests.post("https://payments.example.com/charge", json={"amount": amount}, headers=headers)


def main():
    call_payment_api(19.99)


if __name__ == "__main__":
    main()
