import logging
from flask import Flask, request

app = Flask(__name__)
logger = logging.getLogger(__name__)


@app.route("/search")
def search():
    q = request.args.get("q")
    logger.info("search query: " + q)
    return "ok"
