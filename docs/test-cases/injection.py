# Test case: injection (A05:2025)
import sqlite3
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/users")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    # BUG: SQL injection via string formatting
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return jsonify(conn.execute(query).fetchone())

@app.route("/convert")
def convert_file():
    filename = request.args.get("filename")
    # BUG: shell injection via user-controlled input
    result = subprocess.check_output(f"convert {filename} output.png", shell=True)
    return result

@app.route("/render")
def render_template():
    name = request.args.get("name")
    from jinja2 import Template
    # BUG: server-side template injection
    template = Template(f"Hello {name}!")
    return template.render()
