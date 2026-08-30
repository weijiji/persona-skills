from datetime import timedelta
from flask import Flask

app = Flask(__name__)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)


if __name__ == "__main__":
    app.run()
