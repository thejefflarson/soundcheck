# Test case: hotspots (A06:2025)
# A small app with several security-sensitive areas that hotspot analysis should flag.
import os
import hashlib
import pickle
import sqlite3
import requests
from flask import Flask, request, jsonify, session

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "changeme")

DB = sqlite3.connect("app.db")

# --- TRUST BOUNDARY: route handlers accepting user input ---

@app.route("/search")
def search():
    q = request.args.get("q")
    results = DB.execute(f"SELECT * FROM items WHERE name LIKE '%{q}%'").fetchall()
    return jsonify(results)

# --- AUTH & SESSIONS ---

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    hashed = hashlib.md5(password.encode()).hexdigest()
    user = DB.execute("SELECT * FROM users WHERE name=? AND pass=?", [username, hashed]).fetchone()
    if user:
        session["user_id"] = user[0]
        return jsonify({"ok": True})
    return jsonify({"error": "bad credentials"}), 401

# --- ACCESS CONTROL ---

@app.route("/users/<int:user_id>/profile")
def get_profile(user_id):
    # No ownership check — any logged-in user can view any profile
    row = DB.execute("SELECT * FROM users WHERE id=?", [user_id]).fetchone()
    return jsonify(row)

# --- DATA LAYER: deserialization ---

@app.route("/import", methods=["POST"])
def import_data():
    data = pickle.loads(request.data)
    return jsonify({"imported": len(data)})

# --- CRYPTO & SECRETS ---

API_KEY = "sk-live-hardcoded-key-12345"

def generate_token():
    import random
    return hashlib.sha1(str(random.random()).encode()).hexdigest()

# --- EXTERNAL CALLS ---

@app.route("/proxy")
def proxy():
    url = request.args.get("url")
    resp = requests.get(url)
    return resp.text

@app.route("/notify", methods=["POST"])
def notify():
    payload = request.json
    requests.post("https://hooks.slack.com/services/T00/B00/xxx", json=payload)
    return jsonify({"sent": True})
