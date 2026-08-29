from flask import Flask, request

app = Flask(__name__)


@app.route("/calc")
def calc():
    user_expr = request.args.get("expr")
    return str(eval(user_expr))


if __name__ == "__main__":
    app.run()
