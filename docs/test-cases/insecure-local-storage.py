# insecure-local-storage test case
# Each function below stores sensitive data using an insecure method.
# The skill should fire and rewrite these to use platform-secure storage.

import json
import os
import tempfile
import sqlite3


# Credentials written to a plaintext JSON file
def save_api_key(api_key):
    with open(os.path.expanduser("~/.myapp/config.json"), "w") as f:
        json.dump({"api_key": api_key}, f)


# Auth token in a world-readable temp file
def cache_token(token):
    tmp = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt")
    tmp.write(f"token={token}")
    tmp.close()
    return tmp.name


# Password stored in unencrypted SQLite
def store_password(username, password):
    conn = sqlite3.connect("users.db")
    conn.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, password),
    )
    conn.commit()


# Session token in a plain environment variable dump
def persist_session(session_token):
    env_file = os.path.expanduser("~/.myapp/.env")
    with open(env_file, "a") as f:
        f.write(f"SESSION_TOKEN={session_token}\n")
