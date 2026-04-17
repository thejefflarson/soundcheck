"""SSRF — intentionally vulnerable. DO NOT deploy."""
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# BUG: fetches any URL the caller supplies — attacker can reach internal services
@app.route("/preview")
def preview_url():
    url = request.args.get("url")
    resp = requests.get(url)  # no validation — http://169.254.169.254/ works
    return jsonify({"status": resp.status_code, "body": resp.text[:500]})

# BUG: webhook callback to attacker-controlled address
@app.route("/webhook/register", methods=["POST"])
def register_webhook():
    callback_url = request.json["callback_url"]
    # No validation — attacker registers http://internal-admin:8080/delete-all
    requests.post(callback_url, json={"event": "registered"})
    return jsonify({"ok": True})

# BUG: follows redirects — attacker uses allowed host that 302s to internal
@app.route("/fetch")
def fetch_resource():
    url = request.args.get("url")
    resp = requests.get(url, allow_redirects=True)  # follows 302 to internal
    return resp.content
