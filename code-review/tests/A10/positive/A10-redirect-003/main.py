from flask import Flask, request, redirect

app = Flask(__name__)


@app.route("/go")
def go():
    next_url = request.values.get("url", "/home")
    return redirect(next_url)
