from flask import Flask, jsonify

app = Flask(__name__)

USERS = {
    1: {"id": 1, "owner": "alice", "email": "alice@example.com"},
    2: {"id": 2, "owner": "bob", "email": "bob@example.com"},
}


@app.route("/users/<int:user_id>")
def get_user(user_id):
    user = USERS.get(user_id)
    if user is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(user)


if __name__ == "__main__":
    app.run()
