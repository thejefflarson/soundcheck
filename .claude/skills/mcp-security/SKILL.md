---
name: mcp-security
description: Use when writing MCP server definitions, tool schemas, or tool handler
  code. Also invoke when registering tools with Claude or building Claude Code extensions
  that expose file system, shell, or network access.
---

# MCP Server Security (OWASP LLM07:2025)

## What this checks

Prevents MCP tool handlers from being exploited via malicious inputs, hardcoded secrets,
unrestricted file access, or shell injection. A compromised MCP server gives attackers
direct access to the host environment.

## Vulnerable patterns

- `open(inputs["path"])` — arbitrary file read from tool parameter with no allowlist
- `subprocess.run(inputs["cmd"], shell=True)` — shell injection from tool input
- `api_key = "sk-abc123..."` — hardcoded secret in handler or tool definition
- Schema `{"type": "string"}` with no `maxLength`, `pattern`, or `enum` — unconstrained input

## Fix immediately

When this skill invokes, rewrite the vulnerable code using the pattern below. Explain
what was wrong and what changed. Then continue with the original task.

**Secure pattern:**

```python
import os, logging
from pathlib import Path

ALLOWED_DIR = Path("/app/data").resolve()
API_KEY = os.environ["SERVICE_API_KEY"]  # never hardcode
logger = logging.getLogger(__name__)

TOOL_SCHEMA = {
    "name": "read_file",
    "input_schema": {
        "type": "object",
        "properties": {
            "filename": {
                "type": "string",
                "maxLength": 128,
                "pattern": r"^[\w\-]+\.(txt|json|csv)$",
            }
        },
        "required": ["filename"],
        "additionalProperties": False,
    },
}

def handle_read_file(inputs: dict) -> str:
    target = (ALLOWED_DIR / inputs["filename"]).resolve()
    if not str(target).startswith(str(ALLOWED_DIR)):
        raise ValueError("Path traversal blocked")
    logger.info("mcp=read_file file=%s", inputs["filename"])
    return target.read_text()
```

**Why this works:** Schema constraints reject malformed inputs before the handler runs.
Path confinement to `ALLOWED_DIR` defeats traversal. Secrets load from environment.
Every invocation is logged.

## Verification

After rewriting, confirm:

- [ ] No secrets hardcoded — all credentials loaded from `os.environ`
- [ ] File paths resolved and confined to an allowed base directory
- [ ] Shell calls use argument lists, not `shell=True` with string input
- [ ] Every schema string parameter has `maxLength`, `pattern`, or `enum`

## References

- CWE-284 ([Improper Access Control](https://cwe.mitre.org/data/definitions/284.html))
- CWE-78 ([OS Command Injection](https://cwe.mitre.org/data/definitions/78.html))
- CWE-200 ([Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html))
- [OWASP LLM07:2025 Insecure Plugin Design](https://genai.owasp.org/llmrisk/llm07-insecure-plugin-design/)
