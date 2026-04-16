---
name: insecure-plugin-design
description: Use when writing LLM tool definitions, function schemas for tool use,
  plugin or extension handlers, or any code that defines what actions an LLM can
  take via tools. Also invoke when implementing tool parameter validation.
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

When this skill invokes, flag the vulnerable code and explain the risk. Show the secure pattern below as a suggested fix. Then continue with the original task.

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

Confirm the following *properties* hold (language-agnostic):

- [ ] Every tool input is constrained at the tool boundary by some concrete mechanism — JSON Schema keywords (`maxLength`/`pattern`/`enum`/`additionalProperties: false`), a typed enum or sealed class in the method signature, runtime regex/length validation at the top of the handler, or an allowlist lookup against a static set — before the value is used
- [ ] Authorization is enforced inside the tool handler itself against the invoking principal — not delegated to the LLM's judgment, not assumed from the caller, and not handled only by an outer framework layer
- [ ] File, path, or resource identifiers supplied by the LLM are canonicalized and verified to fall within an explicit allowed root or allowlist before any I/O — path traversal, symlink escape, and absolute-path injection are all rejected
- [ ] Each tool exposes the narrowest capability that satisfies its purpose — read, write, and destructive operations are separated into distinct tools/handlers rather than multiplexed behind a single `action` parameter
- [ ] Every tool invocation produces an audit record containing the invoking principal, the tool name, and the (sanitized) parameter values, written before the side-effecting operation returns

## References

- CWE-284 ([Improper Access Control](https://cwe.mitre.org/data/definitions/284.html))
- CWE-20 ([Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html))
- [OWASP LLM07:2025 Insecure Plugin Design](https://genai.owasp.org/llmrisk/llm07-insecure-plugin-design/)
