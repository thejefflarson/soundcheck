# pr-review test case
# Mode 1 (PR gate) should flag Critical/High issues in this diff only,
# without dispatching subagents and without emitting Medium/Low findings.
# This file deliberately mixes one Critical, one High, one Medium, and one
# Low so the gate is observed to filter by severity.

import sqlite3
import os
import hashlib

# Critical: SQL injection via string concatenation (skill: injection)
def get_user(user_id):
    conn = sqlite3.connect("users.db")
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    return conn.execute(query).fetchall()


# High: shell command built from a request parameter (skill: injection)
def export_report(filename):
    os.system("zip reports.zip " + filename)


# High: hardcoded credential committed to source (skill: hardcoded-secrets)
API_TOKEN = "sk-prod-7f3c1a9b4d2e8f5c0a6b3d2e1f4c5a6b"


# Medium: MD5 password hashing — pr-review should NOT emit this in mode 1.
# (skill: cryptographic-failures) Mode 2 catches it; mode 1 deliberately
# does not.
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


# Low: log line missing structured context — pr-review should NOT emit
# this either. Mode 2's design-review surfaces it.
def log_failed_login(username):
    print("login failed for " + username)
