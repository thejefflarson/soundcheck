# Test case: authentication-failures (A07:2025)
import hashlib
import jwt
from flask import Flask, jsonify

app = Flask(__name__)

# BUG: MD5 for password storage
def store_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# BUG: hardcoded weak JWT secret, no algorithm restriction
JWT_SECRET = "secret"

def create_token(user_id):
    return jwt.encode({"user_id": user_id}, JWT_SECRET)

def verify_token(token):
    # BUG: no algorithm allowlist — vulnerable to alg:none attack
    return jwt.decode(token, JWT_SECRET, options={"verify_signature": False})

@app.route("/logout", methods=["POST"])
def logout():
    # BUG: session not invalidated server-side
    return jsonify({"message": "Logged out"})
