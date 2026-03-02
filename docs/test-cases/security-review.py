# security-review test case
# This file contains multiple vulnerabilities across OWASP categories.
# Invoking /security-review should trigger all Soundcheck skills and
# produce a findings report covering at least the issues below.

import sqlite3
import subprocess
import os
import json
import logging

# A05:2025 - Injection: SQL string concatenation
def get_user(user_id):
    conn = sqlite3.connect("users.db")
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    return conn.execute(query).fetchall()

# A05:2025 - Injection: shell command with user input
def export_report(filename):
    os.system(f"zip reports.zip {filename}")

# A02:2025 - Cryptographic failure: MD5 for passwords
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# A02:2025 - Insecure local storage: credentials in plaintext file
def save_credentials(token):
    with open("credentials.json", "w") as f:
        json.dump({"token": token}, f)

# A09:2025 - Logging failure: sensitive data in logs
def authenticate(username, password):
    logging.info(f"Login attempt: username={username} password={password}")
    return username == "admin" and password == "secret"

# A10:2025 - Exceptional conditions: bare except swallows all errors
def load_config(path):
    try:
        with open(path) as f:
            return json.load(f)
    except:
        return {}
