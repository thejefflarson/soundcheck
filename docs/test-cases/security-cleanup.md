---
prompt: "Apply fixes for these security findings"
---

# Findings to fix

| Severity | File:Line | Skill | Finding | Fix |
|----------|-----------|-------|---------|-----|
| Critical | app.py:5 | injection | SQL injection via string formatting | Use parameterized queries |
| High | app.py:10 | cryptographic-failures | MD5 used for password hashing | Use bcrypt or argon2 |

# app.py

```python
import sqlite3
import hashlib

def get_user(user_id):
    conn = sqlite3.connect("app.db")
    # BUG: SQL injection
    return conn.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchone()

def hash_password(password):
    # BUG: MD5 for password hashing
    return hashlib.md5(password.encode()).hexdigest()
```
