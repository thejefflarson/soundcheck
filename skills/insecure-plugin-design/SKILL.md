---
name: insecure-plugin-design
description: Use when writing LLM tool definitions, function schemas for tool use,
  plugin or extension handlers, or any code that defines what actions an LLM can
  take via tools. Also invoke when implementing tool parameter validation or access
  controls for LLM-callable functions.
---

# Insecure Plugin Design (OWASP LLM07:2025)

## What this checks

Prevents LLM tools and plugins from being abused via malicious or malformed inputs
driven by prompt injection or jailbreaks. Unvalidated tool parameters let an attacker
escalate from a chat window to arbitrary file access, command execution, or data
exfiltration.

## Vulnerable patterns

- Tool handler accepts raw `str` path parameter with no allowlist — enables path traversal
- No authorization check inside the tool function itself (relies only on the LLM to decide)
- Tool schema uses `"type": "string"` with no `enum`, `maxLength`, or pattern constraints
- A single tool exposes read + write + delete with no scope separation

## Fix immediately

When this skill invokes, rewrite the vulnerable code using the pattern below. Explain
what was wrong and what changed. Then continue with the original task.

**Secure pattern:**

```python
import logging
from pathlib import Path

ALLOWED_DIR = Path("/app/data").resolve()
logger = logging.getLogger(__name__)

# Tool schema — tight constraints declared upfront
READ_FILE_SCHEMA = {
    "name": "read_file",
    "description": "Read a file from the allowed data directory.",
    "parameters": {
        "type": "object",
        "properties": {
            "filename": {
                "type": "string",
                "maxLength": 128,
                "pattern": r"^[\w\-]+\.(txt|csv|json)$",  # allowlist extensions
            }
        },
        "required": ["filename"],
        "additionalProperties": False,
    },
}

# Tool handler — validate, authorize, log
def read_file(filename: str, *, current_user) -> str:
    if not current_user.has_permission("file:read"):
        raise PermissionError("Unauthorized")

    target = (ALLOWED_DIR / filename).resolve()
    if not str(target).startswith(str(ALLOWED_DIR)):
        raise ValueError("Path traversal detected")

    logger.info("tool=read_file user=%s file=%s", current_user.id, filename)
    return target.read_text()
```

**Why this works:** Schema constraints reject malformed inputs before the handler
runs. The resolved-path check defeats traversal. Authorization is enforced inside
the handler — never delegated to the LLM's judgment. Every invocation is logged.

## Verification

After rewriting, confirm:

- [ ] Tool schemas declare `maxLength`, `pattern`, or `enum` on every string parameter
- [ ] Authorization is checked at the start of every tool handler function
- [ ] File/path parameters are resolved and confined to an allowed base directory
- [ ] All tool invocations are logged with user identity and parameter values

## References

- CWE-284 ([Improper Access Control](https://cwe.mitre.org/data/definitions/284.html))
- CWE-20 ([Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html))
- [OWASP LLM07:2025 Insecure Plugin Design](https://genai.owasp.org/llmrisk/llm07-insecure-plugin-design/)
