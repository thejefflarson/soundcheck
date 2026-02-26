---
name: injection
description: Use when writing code that constructs database queries, builds SQL strings,
  executes shell commands, processes templates with user input, evaluates code dynamically,
  or passes user-controlled data to any external interpreter. Also invoke when reviewing
  ORM raw queries or NoSQL filter objects.
---

# Injection Security Check (A05:2025)

## What this checks

Protects against SQL, command, template, and NoSQL injection caused by passing
user-controlled data to an interpreter without sanitization. Exploitation leads to
full database read/write, remote code execution, and data exfiltration.

## Vulnerable patterns

- `f"SELECT * FROM users WHERE id = {user_id}"` — user input concatenated directly into SQL
- `subprocess.call(f"convert {filename}", shell=True)` — shell expansion allows `; rm -rf /`
- `eval(user_input)` — arbitrary code execution from user-supplied string
- `db.collection.find({"role": request.json["role"]})` — NoSQL operator injection (`{"$ne": null}`)

## Fix immediately

When this skill invokes, rewrite the vulnerable code using the pattern below. Explain
what was wrong and what changed. Then continue with the original task.

**Secure pattern:**

```python
# SQL — parameterized query (never concatenate)
cursor.execute("SELECT * FROM users WHERE id = %s AND active = %s", (user_id, True))

# SQL — SQLAlchemy ORM (preferred)
user = db.session.execute(
    select(User).where(User.id == user_id, User.active == True)
).scalar_one_or_none()

# Shell — list args, no shell=True
import subprocess, shlex
result = subprocess.run(
    ["convert", filename, "-resize", "800x600", output_path],
    capture_output=True, timeout=30
)   # no shell expansion; each arg is a discrete value

# Template — autoescaping (Jinja2)
from jinja2 import Environment
env = Environment(autoescape=True)   # HTML-escapes {{ user_content }} automatically
tmpl = env.from_string("<p>{{ message }}</p>")

# NoSQL — explicit type validation before query
from pydantic import BaseModel
class SearchParams(BaseModel):
    role: str   # pydantic rejects non-string values
params = SearchParams(**request.json)
db.users.find({"role": params.role})
```

**Why this works:** Parameterized queries send data and code on separate channels;
the database never interprets data as SQL. List-form `subprocess` bypasses the shell
entirely. Autoescaping and schema validation ensure user data cannot be interpreted
as interpreter syntax.

## Verification

After rewriting, confirm:

- [ ] No string concatenation or f-strings used to build SQL — only `%s` / `:param` placeholders
- [ ] All `subprocess` calls use a list for `args` and `shell=False` (the default)
- [ ] No `eval`, `exec`, or `__import__` called with user-supplied strings
- [ ] Jinja2 / Twig / Handlebars environments have autoescaping enabled
- [ ] NoSQL filter values are validated against a strict schema before the query executes

## References

- CWE-89 ([SQL Injection](https://cwe.mitre.org/data/definitions/89.html))
- CWE-78 ([OS Command Injection](https://cwe.mitre.org/data/definitions/78.html))
- CWE-94 ([Code Injection](https://cwe.mitre.org/data/definitions/94.html))
- [OWASP A05:2025 Injection](https://owasp.org/Top10/A03_2021-Injection/)
