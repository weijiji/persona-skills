from flask import Flask, redirect

app = Flask(__name__)


@app.route("/about")
def about():
    return redirect("/about/team")
