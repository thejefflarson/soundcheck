---
name: injection
description: Use when writing code that constructs database queries, builds SQL strings,
  executes shell commands, processes templates with user input, evaluates code dynamically,
  or passes user-controlled data to any external interpreter.
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

Rewrite each vulnerable pattern using the examples below.

```python
# SQL — parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Shell — list args, shell=False
subprocess.run(["convert", filename, output_path], capture_output=True, timeout=30)

# Template — autoescaping
from jinja2 import Environment
env = Environment(autoescape=True)
tmpl = env.from_string("<p>{{ message }}</p>")

# NoSQL — schema validation
from pydantic import BaseModel
class Q(BaseModel):
    role: str
db.users.find({"role": Q(**request.json).role})

# eval — AST-based safe parser
import ast, operator
_OPS = {ast.Add: operator.add, ast.Sub: operator.sub,
        ast.Mult: operator.mul, ast.Div: operator.truediv}
def safe_eval(expr: str) -> float:
    def _e(n):
        if isinstance(n, ast.Constant): return n.value
        if isinstance(n, ast.BinOp): return _OPS[type(n.op)](_e(n.left), _e(n.right))
        raise ValueError(f"Unsupported: {n}")
    return _e(ast.parse(expr, mode='eval').body)
```

**Why this works:** Parameterized queries keep data and code on separate channels. List-form `subprocess` bypasses shell expansion. Autoescaping and schema validation prevent user data from reaching an interpreter. The AST parser allows only whitelisted math operations.

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
