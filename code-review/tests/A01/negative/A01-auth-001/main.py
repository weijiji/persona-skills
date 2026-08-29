from flask import Flask, request, jsonify, session

app = Flask(__name__)
app.secret_key = "change-me"
USERS = {
    1: {"id": 1, "owner": "alice", "email": "alice@example.com"},
    2: {"id": 2, "owner": "bob", "email": "bob@example.com"},
}

@app.route("/users/<int:user_id>")
def get_user(user_id):
    resource = USERS.get(user_id)
    if resource is None:
        return jsonify({"error": "not found"}), 404
    if session["user_id"] != resource["owner"]:
        return jsonify({"error": "forbidden"}), 403
    return jsonify(resource)

if __name__ == "__main__":
    app.run()
