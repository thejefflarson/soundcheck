---
name: insecure-output-handling
description: Use when writing code that renders LLM output to a UI, executes LLM-generated
  code or shell commands, or passes LLM responses to downstream APIs or databases.
  Also invoke when displaying markdown or HTML from an LLM response.
---

# Insecure Output Handling Security Check (OWASP LLM02:2025)

## What this checks

Protects against XSS, command injection, and second-order injection that arise when
LLM output is treated as trusted. The model may produce malicious content through
prompt injection or hallucination; downstream systems must sanitize it the same way
they would sanitize raw user input.

## Vulnerable patterns

- `element.innerHTML = llmResponse` — injects attacker-controlled HTML/JS into the DOM
- `exec(llm_generated_code)` or `subprocess.run(llm_command, shell=True)` — arbitrary code execution
- `db.execute(f"SELECT * FROM {llm_output}")` — LLM output lands in a SQL statement unsanitized
- Rendering LLM-produced markdown in a `dangerouslySetInnerHTML` prop without sanitization

## Fix immediately

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **Treat LLM output as untrusted input at every consumption point.** The same
   escaping, parameterization, and allowlisting rules that apply to user input
   apply here — prompt injection makes the model a proxy for attacker content.
2. **HTML rendering uses a safe sink.** `textContent` / auto-escaping template
   for plain text; a sanitizer (DOMPurify, bleach) for rich content. Never
   `innerHTML`, `dangerouslySetInnerHTML`, or `v-html` with a raw LLM string.
3. **Shell and code execution require an allowlist.** If the LLM picks an
   action, the handler validates it against a static set of permitted commands
   and invokes them with argv arrays — never `shell=True`, never `eval`, never
   `os.system(raw_output)`.
4. **Database queries are parameterized.** LLM output lands in bind variables,
   not string-interpolated into the statement. For injection details, see the
   `injection` skill.

Anchor — shape, not implementation:

```
# HTML
element.textContent = llm_out                       # or sanitize(llm_out) for rich
# shell
require(parse(llm_out)[0] in ALLOWED_COMMANDS)
run(parse(llm_out), shell=False, timeout=10)
# SQL
db.execute("SELECT ... WHERE name = ?", [llm_out])  # parameterized
```

## Verification

Confirm the response:

- [ ] No LLM string is assigned to `innerHTML` or `dangerouslySetInnerHTML` without `DOMPurify.sanitize`
- [ ] Shell execution uses an allowlist; `shell=True` is never passed with LLM-derived input
- [ ] If the code routes LLM output into a database query, the query uses parameterized placeholders — not an f-string or concatenation with the LLM-derived value. Skip this criterion when the code does not execute any database query.
- [ ] LLM output is treated as untrusted user input at every consumption point

## References

- CWE-79 ([Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html))
- CWE-116 ([Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html))
- [OWASP LLM02:2025 Insecure Output Handling](https://genai.owasp.org/llmrisk/llm02-insecure-output-handling/)
