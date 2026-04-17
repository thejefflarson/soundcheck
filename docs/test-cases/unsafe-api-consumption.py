"""Unsafe API consumption — intentionally vulnerable. DO NOT deploy."""
import requests
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)
db = sqlite3.connect(":memory:")

# BUG: external API data injected directly into SQL
@app.route("/sync-products")
def sync_products():
    resp = requests.get("https://api.partner.com/products")
    for product in resp.json():
        # No validation — attacker compromises partner API, injects SQL
        db.execute(
            f"INSERT INTO products (name, price) VALUES ('{product['name']}', {product['price']})"
        )
    return jsonify({"synced": True})

# BUG: rendering external HTML without sanitization
@app.route("/embed-review")
def embed_review():
    resp = requests.get("https://api.reviews.com/latest")
    review_html = resp.json()["html"]
    # XSS via compromised review API
    return f"<div class='review'>{review_html}</div>"

# BUG: following redirect from untrusted API response
@app.route("/partner-redirect")
def partner_redirect():
    resp = requests.get("https://api.partner.com/auth-url")
    redirect_url = resp.json()["url"]
    # Open redirect — partner API returns http://evil.com
    return app.redirect(redirect_url)

# BUG: merging external data into internal model without allowlist
@app.route("/import-user")
def import_user():
    resp = requests.get(f"https://api.partner.com/users/{request.args['id']}")
    user_data = resp.json()
    # Mass assignment from external API — could set is_admin=true
    db.execute(
        "INSERT INTO users ({}) VALUES ({})".format(
            ", ".join(user_data.keys()),
            ", ".join(f"'{v}'" for v in user_data.values()),
        )
    )
    return jsonify({"imported": True})
