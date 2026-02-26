# Test case: insecure-design (A06:2025)
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")
    # BUG: no rate limiting, no lockout after failed attempts
    user = db.find_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404  # BUG: reveals user existence
    if user.password != password:
        return jsonify({"error": "Wrong password"}), 401
    return jsonify({"token": generate_token(user)})

@app.route("/transfer", methods=["POST"])
def transfer_funds():
    # BUG: no re-authentication for high-value operation
    from_account = request.json.get("from")
    to_account = request.json.get("to")
    amount = request.json.get("amount")
    db.transfer(from_account, to_account, amount)
    return jsonify({"status": "transferred"})
