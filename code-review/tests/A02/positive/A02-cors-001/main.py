from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app, allow_origins=["*"])


@app.route("/")
def index():
    return "hello"


if __name__ == "__main__":
    app.run()
