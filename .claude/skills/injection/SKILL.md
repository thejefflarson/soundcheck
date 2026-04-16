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
- **Templates**: use an engine that autoescapes by default and pass user values through the parameter interface. Python: `Environment(autoescape=True)` (bool literal, not `select_autoescape()` with `from_string()`). Go: `html/template`, never `text/template` for HTTP output. Java FreeMarker: `cfg.setOutputFormat(HTMLOutputFormat.INSTANCE)`. Rust: `handlebars` (escapes by default). Never build the template body from user input.
- **NoSQL**: validate filter values against a strict schema before the query executes
- **eval/exec**: remove entirely — there is no safe way to evaluate user-supplied code strings

Rewrite the vulnerable call site in place, explain what changed, then continue.

## Verification

After rewriting, confirm the following *properties* hold (language-agnostic):

- [ ] User-controlled values reach SQL only as bound parameters — never via string interpolation, concatenation, or format strings
- [ ] User-controlled values reach subprocess execution only as discrete argument list elements — never via a shell string or interpolated command string
- [ ] No dynamic evaluation of user-supplied strings as code (Python `eval`/`exec`, JS `eval`/`new Function`, etc. removed — not replaced with a safer-looking variant of the same function)
- [ ] Templates use an engine where HTML autoescaping is either enabled explicitly or is the documented default (Flask `render_template`, Go `html/template`, Rust `handlebars`, Jinja2 `Environment(autoescape=True)` — NOT Jinja2 `Template()` direct, NOT Go `text/template`), and user values are passed through the engine's parameter interface — never by building the template body from user input
- [ ] Structured-query filters (NoSQL, GraphQL, LDAP) validate user-supplied keys and values against a schema before reaching the query builder

## References

- CWE-89 ([SQL Injection](https://cwe.mitre.org/data/definitions/89.html))
- CWE-78 ([OS Command Injection](https://cwe.mitre.org/data/definitions/78.html))
- CWE-94 ([Code Injection](https://cwe.mitre.org/data/definitions/94.html))
- [OWASP A05:2025 Injection](https://owasp.org/Top10/A03_2021-Injection/)
