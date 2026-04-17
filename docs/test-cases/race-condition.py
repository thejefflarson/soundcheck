"""Race condition — intentionally vulnerable. DO NOT deploy."""
import os
import sqlite3

db = sqlite3.connect(":memory:")

# BUG: TOCTOU — file can be swapped between check and read
def read_if_exists(path: str) -> str:
    if os.path.exists(path):
        with open(path) as f:
            return f.read()
    return ""

# BUG: double-spend — read-modify-write without locking
def transfer(from_id: int, to_id: int, amount: float):
    cursor = db.cursor()
    cursor.execute("SELECT balance FROM accounts WHERE id = ?", (from_id,))
    balance = cursor.fetchone()[0]
    if balance >= amount:
        # Another request can read the same balance before this write
        cursor.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?",
                       (amount, from_id))
        cursor.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?",
                       (amount, to_id))
        db.commit()

# BUG: check-then-create race — duplicate users
def create_user(username: str):
    cursor = db.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cursor.fetchone() is None:
        # Another request can insert between SELECT and INSERT
        cursor.execute("INSERT INTO users (username) VALUES (?)", (username,))
        db.commit()
