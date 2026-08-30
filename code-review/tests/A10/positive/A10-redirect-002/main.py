from flask import Flask, request, redirect

app = Flask(__name__)


@app.route("/leave")
def leave():
    return redirect(request.form["url"])
