import requests

API_KEY = "sk-test-1234567890abcdef"


def call_payment_api(amount):
    headers = {"Authorization": f"Bearer {API_KEY}"}
    return requests.post(
        "https://payments.example.com/charge",
        json={"amount": amount},
        headers=headers,
    )


def main():
    call_payment_api(19.99)


if __name__ == "__main__":
    main()
