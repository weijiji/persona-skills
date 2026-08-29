from flask import Flask, request, jsonify

app = Flask(__name__)

def login_required(func):
    def wrapper(*args, **kwargs):
        if request.headers.get("X-User") is None:
            return jsonify({"error": "unauthorized"}), 401
        return func(*args, **kwargs)
    return wrapper

@app.route("/admin/reports")
@login_required
def reports():
    role = request.headers.get("X-Role")
    if role != "admin":
        return jsonify({"error": "forbidden"}), 403
    return jsonify({"report": "Q3 summary"})

if __name__ == "__main__":
    app.run()
