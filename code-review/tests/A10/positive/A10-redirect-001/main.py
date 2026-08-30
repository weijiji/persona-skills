from flask import Flask, request, redirect

app = Flask(__name__)


@app.route("/goto")
def goto():
    target = request.args.get("next")
    return redirect(target)
