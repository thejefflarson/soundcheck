# Test case: broken-access-control (A01:2025)
# Missing ownership check — any authenticated user can read any document
from flask import Flask, request, jsonify
import db

app = Flask(__name__)

@app.route("/documents/<int:doc_id>")
def get_document(doc_id):
    user_id = request.headers.get("X-User-Id")
    # BUG: no ownership check — user_id is ignored after auth
    doc = db.query("SELECT * FROM documents WHERE id = ?", [doc_id])
    return jsonify(doc)

@app.route("/admin/users")
def list_users():
    # BUG: no role check — any authenticated user can list all users
    users = db.query("SELECT id, email FROM users")
    return jsonify(users)

# SSRF: fetches any user-supplied URL
@app.route("/preview")
def preview_url():
    url = request.args.get("url")
    import requests
    return requests.get(url).text
