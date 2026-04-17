"""NoSQL injection — intentionally vulnerable. DO NOT deploy."""
from flask import Flask, request, jsonify
from pymongo import MongoClient

app = Flask(__name__)
db = MongoClient().myapp

# BUG: raw request body passed as query filter — operator injection
@app.route("/login", methods=["POST"])
def login():
    user = request.json.get("username")
    passwd = request.json.get("password")
    # Attacker sends {"password": {"$ne": ""}} to bypass auth
    account = db.users.find_one({"username": user, "password": passwd})
    if account:
        return jsonify({"ok": True})
    return jsonify({"ok": False}), 401

# BUG: $where with user input — JavaScript injection in MongoDB
@app.route("/search")
def search():
    name = request.args.get("name")
    # Attacker: name='; return true; var x='
    results = db.users.find({"$where": f"this.name == '{name}'"})
    return jsonify([r["name"] for r in results])

# BUG: raw query params as filter — arbitrary operator injection
@app.route("/filter")
def filter_items():
    query = dict(request.args)
    # Attacker: ?price[$gt]=0 returns all items
    return jsonify(list(db.products.find(query)))
