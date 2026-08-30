from flask import Flask, request, redirect

app = Flask(__name__)

ALLOWED = {"github": "https://github.com", "docs": "https://docs.example.com"}


@app.route("/link")
def link():
    key = request.args.get("site")
    target = ALLOWED.get(key)
    if target is None:
        return "bad", 400
    return redirect(target)
