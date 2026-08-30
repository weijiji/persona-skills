import requests


def fetch(api_url: str):
    return requests.get(api_url, verify=False)
