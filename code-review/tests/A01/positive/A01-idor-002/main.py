from flask import Flask, request, jsonify

app = Flask(__name__)

ORDERS = {
    100: {"id": 100, "customer": "alice", "total": 250.0},
    200: {"id": 200, "customer": "bob", "total": 90.5},
}

def get_order(order_id):
    return ORDERS.get(order_id)

@app.route("/orders")
def orders():
    order_id = request.args.get("order_id")
    return jsonify(get_order(order_id))

if __name__ == "__main__":
    app.run()
