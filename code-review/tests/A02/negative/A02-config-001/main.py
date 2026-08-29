import os

from flask import Flask

app = Flask(__name__)
app.config["ENV"] = os.environ.get("FLASK_ENV", "production")


@app.route("/")
def index():
    return "hello"


if __name__ == "__main__":
    app.run(debug=False)
