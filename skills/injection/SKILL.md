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

- `"SELECT * FROM users WHERE id = " + userId` — user input concatenated into SQL
- `exec("convert " + filename)` — shell expansion allows `; rm -rf /`
- `eval(userInput)` — arbitrary code execution from user-supplied string
- `db.find({role: req.body.role})` — NoSQL operator injection (`{"$ne": null}`)

## Fix immediately

For each vulnerable call site, apply the appropriate control:

- **SQL**: use parameterized queries or an ORM — never concatenate user input into query strings
- **Shell**: pass arguments as an array/list, never as an interpolated string — disable shell expansion
- **Templates**: enable autoescaping — never construct template strings from user input
- **NoSQL**: validate filter values against a strict schema before the query executes
- **eval/exec**: remove entirely — there is no safe way to evaluate user-supplied code strings

Rewrite the vulnerable call site in place, explain what changed, then continue.

## Verification

After rewriting, confirm:

- [ ] No string interpolation or concatenation used to build SQL — only parameterized placeholders
- [ ] Shell commands pass arguments as an array, not as an interpolated string
- [ ] No `eval()` or `exec()` anywhere in the rewritten code — removed entirely, not replaced with a safer variant
- [ ] Template rendering uses autoescaping and passes user values as named arguments, never via string concatenation
- [ ] NoSQL filter values are validated against a strict schema before the query executes

## References

- CWE-89 ([SQL Injection](https://cwe.mitre.org/data/definitions/89.html))
- CWE-78 ([OS Command Injection](https://cwe.mitre.org/data/definitions/78.html))
- CWE-94 ([Code Injection](https://cwe.mitre.org/data/definitions/94.html))
- [OWASP A05:2025 Injection](https://owasp.org/Top10/A03_2021-Injection/)
