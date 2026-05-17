---
name: mcp-security
description: Detects MCP tool handlers vulnerable to malicious inputs, hardcoded secrets,
  or unrestricted file/shell access. Use when writing MCP server definitions,
  tool schemas, or tool handler code. Also invoke when registering tools with
  Claude or building Claude Code extensions that expose file system, shell, or
  network access.
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

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **Tool schemas constrain every string parameter** — `maxLength`, `pattern`,
   `enum`, or `additionalProperties: false`. A bare `"type": "string"` is a blank
   check. The schema is the first line of defense because the model generated the
   input.
2. **Paths are canonicalized and confined to an allowed root.** The handler
   resolves the supplied filename against a fixed base directory and verifies the
   result stays inside that directory — defeating `../`, symlink escape, and
   absolute paths.
3. **Shell execution uses argument lists, never `shell=True` with string input.**
   If the tool must run a command, the command name comes from a static
   allowlist and arguments go through argv, not string interpolation.
4. **Secrets come from the environment or a secrets manager** — never hardcoded
   literals in the handler or tool definition. A leaked MCP server config
   shouldn't leak credentials.
5. **Every invocation is audit-logged** with the tool name and sanitized inputs
   before the side-effect runs. For broader MCP tool design guidance, see the
   `insecure-plugin-design` skill.

Anchor — shape, not implementation:

```
schema: { filename: { type: string, maxLength: 128, pattern: "^[\\w-]+\\.(txt|csv)$" } }
API_KEY = load_from_env("SERVICE_API_KEY")

def read_file(inputs):
    target = (ALLOWED_ROOT / inputs["filename"]).resolve()
    require(target.is_relative_to(ALLOWED_ROOT))
    audit_log("read_file", inputs["filename"])
    return target.read()
```

## Verification

Confirm the response:

- [ ] No secrets hardcoded — all credentials loaded from `os.environ`
- [ ] File paths resolved and confined to an allowed base directory
- [ ] Shell calls use argument lists, not `shell=True` with string input
- [ ] Every schema string parameter has `maxLength`, `pattern`, or `enum`

## References

- CWE-284 ([Improper Access Control](https://cwe.mitre.org/data/definitions/284.html))
- CWE-78 ([OS Command Injection](https://cwe.mitre.org/data/definitions/78.html))
- CWE-200 ([Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html))
- [OWASP LLM07:2025 Insecure Plugin Design](https://genai.owasp.org/llmrisk/llm07-insecure-plugin-design/)
