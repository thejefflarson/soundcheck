# Test case: logging-failures (A09:2025)
import logging
from flask import Flask, request, jsonify

app = Flask(__name__)
logger = logging.getLogger(__name__)

@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")
    # BUG: logs password in plaintext
    logger.info(f"Login attempt: username={username}, password={password}")

    user = authenticate(username, password)
    if not user:
        # BUG: failed auth not logged as security event
        return jsonify({"error": "Invalid credentials"}), 401

    # BUG: no log of successful authentication
    return jsonify({"token": create_token(user)})

@app.route("/api/data")
def get_data():
    # BUG: logs full request headers and body, potentially including PII/tokens
    logger.debug(f"Request: {request.headers} {request.get_json()}")
    return jsonify(fetch_data())

@app.route("/profile")
def get_profile():
    username = request.args.get("username", "")
    # BUG: CRLF injection — attacker passes username="alice\nINFO:root: Admin logged in"
    # to forge log entries and obscure malicious activity
    logger.info(f"Profile viewed: username={username}")
    return jsonify(fetch_profile(username))
