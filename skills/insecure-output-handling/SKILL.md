---
name: insecure-output-handling
description: Use when writing code that renders LLM output to a UI, executes LLM-generated
  code or shell commands, or passes LLM responses to downstream APIs or databases.
  Also invoke when displaying markdown or HTML from an LLM response or using LLM output
  as input to another system.
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

When this skill invokes, rewrite the vulnerable code using the pattern below. Explain
what was wrong and what changed. Then continue with the original task.

**Secure pattern:**

```python
import html
import subprocess
import shlex
from typing import Literal

# --- Web rendering (Python / Jinja2 equivalent logic) ---
def render_llm_text(response: str) -> str:
    """Escape before inserting into HTML context."""
    return html.escape(response)          # never use response directly as innerHTML

# --- JavaScript (use DOMPurify for HTML, textContent for plain text) ---
# WRONG:  element.innerHTML = llmResponse;
# RIGHT:
#   element.textContent = llmResponse;                     // plain text, no parse
#   element.innerHTML = DOMPurify.sanitize(llmResponse);  // when HTML is required

# --- Shell command construction ---
ALLOWED_COMMANDS: set[str] = {"ls", "cat", "echo"}

def run_llm_suggested_command(llm_output: str) -> str:
    parts = shlex.split(llm_output)
    if not parts or parts[0] not in ALLOWED_COMMANDS:
        raise ValueError(f"Command not permitted: {parts[0] if parts else '(empty)'}")
    result = subprocess.run(parts, capture_output=True, text=True, timeout=10)
    return result.stdout

# --- Database query (always use parameterized queries) ---
def query_with_llm_filter(column: Literal["name", "status"], value: str):
    allowed_columns = {"name", "status"}
    if column not in allowed_columns:
        raise ValueError(f"Column not allowed: {column}")
    # value goes into a parameter placeholder, never string-formatted into SQL
    return db.execute("SELECT * FROM items WHERE ? = ?", (column, value)).fetchall()
```

**Why this works:** `textContent` and `html.escape` stop XSS without blocking legitimate
text. The command allowlist ensures the model can only trigger pre-approved operations.
Parameterized queries eliminate SQL injection regardless of what the LLM produces.

## Verification

After rewriting, confirm:

- [ ] No LLM string is assigned to `innerHTML` or `dangerouslySetInnerHTML` without `DOMPurify.sanitize`
- [ ] Shell execution uses an allowlist; `shell=True` is never passed with LLM-derived input
- [ ] All database queries use parameterized placeholders, not f-strings with LLM output
- [ ] LLM output is treated as untrusted user input at every consumption point

## References

- CWE-79 ([Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html))
- CWE-116 ([Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html))
- [OWASP LLM02:2025 Insecure Output Handling](https://genai.owasp.org/llmrisk/llm02-insecure-output-handling/)
