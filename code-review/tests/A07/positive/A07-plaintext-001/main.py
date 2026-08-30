from flask import Flask, request

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    pwd = request.form["password"]
    if pwd == "letmein123":
        return "welcome", 200
    return "denied", 401


if __name__ == "__main__":
    app.run()
