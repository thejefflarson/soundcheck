"""Path traversal — intentionally vulnerable. DO NOT deploy."""
import os
from flask import Flask, request, send_file

app = Flask(__name__)
UPLOAD_DIR = "/app/uploads"

# BUG: user-supplied filename allows ../../../etc/passwd
@app.route("/download")
def download():
    filename = request.args.get("file")
    path = os.path.join(UPLOAD_DIR, filename)  # join doesn't prevent traversal
    return send_file(path)

# BUG: absolute path ignores base directory entirely
@app.route("/read")
def read_file():
    filepath = request.args.get("path")
    full = os.path.join(UPLOAD_DIR, filepath)  # /etc/passwd ignores UPLOAD_DIR
    with open(full) as f:
        return f.read()

# BUG: symlink escape — attacker uploads symlink pointing outside root
@app.route("/serve/<name>")
def serve(name):
    path = os.path.join(UPLOAD_DIR, name)
    # No symlink check — symlink could point to /etc/shadow
    return send_file(path)
