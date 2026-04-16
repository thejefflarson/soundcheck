# Test case: file-upload (A04:2025)
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

UPLOAD_DIR = "static/uploads"  # BUG: uploads stored in webroot


@app.route("/upload", methods=["POST"])
def upload_file():
    f = request.files["file"]
    # BUG: no extension validation — attacker can upload .php, .jsp, .html
    # BUG: user-controlled filename used directly — path traversal via ../
    dest = os.path.join(UPLOAD_DIR, f.filename)
    # BUG: no file size limit configured
    f.save(dest)
    return jsonify({"url": f"/static/uploads/{f.filename}"}), 201


@app.route("/avatar", methods=["POST"])
def upload_avatar():
    f = request.files["avatar"]
    # BUG: denylist instead of allowlist — easy to bypass with .phtml, .shtml
    if f.filename.endswith(".exe"):
        return "Not allowed", 400
    # BUG: original filename preserved
    f.save(os.path.join(UPLOAD_DIR, f.filename))
    return "OK"
