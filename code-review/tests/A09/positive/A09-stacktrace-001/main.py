import traceback
from flask import Flask

app = Flask(__name__)


@app.route("/div")
def div():
    try:
        return str(10 / 0)
    except ZeroDivisionError as e:
        return traceback.format_exc()
