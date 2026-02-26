# Test case: exceptional-conditions (A10:2025)
import traceback
from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/process")
def process():
    try:
        data = fetch_data()
        result = transform(data)
        return jsonify(result)
    except Exception as e:
        # BUG: exposes full stack trace to client
        return jsonify({"error": traceback.format_exc()}), 500

@app.route("/admin/delete")
def delete_resource():
    try:
        resource_id = get_resource_id()
        db.delete(resource_id)
    except Exception:
        # BUG: fail-open — returns success even on error
        pass
    return jsonify({"status": "ok"})

@app.errorhandler(404)
def not_found(e):
    # BUG: exposes internal framework version info
    return jsonify({"error": str(e), "server": "Flask/2.3", "python": "3.11"}), 404
