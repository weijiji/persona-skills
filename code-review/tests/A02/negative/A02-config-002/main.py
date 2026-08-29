from flask import Flask
from flask_cors import CORS

app = Flask(__name__)

ALLOWED_ORIGINS = ["https://app.example.com", "https://admin.example.com"]
CORS(app, origins=ALLOWED_ORIGINS)

@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp

@app.route("/")
def index():
    return "hello"

if __name__ == "__main__":
    app.run()
