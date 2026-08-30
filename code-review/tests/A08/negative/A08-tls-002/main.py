import os
import requests


def fetch(api_url: str):
    verify = os.environ.get("VERIFY_SSL", "true") == "true"
    return requests.get(api_url, verify=verify)
