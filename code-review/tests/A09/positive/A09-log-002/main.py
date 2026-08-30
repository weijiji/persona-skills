import logging
from flask import Flask, request

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    logging.error(f"failed login for {username}")
    return "ok", 200
