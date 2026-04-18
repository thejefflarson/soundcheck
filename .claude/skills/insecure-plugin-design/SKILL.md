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

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **Every tool input is constrained at the tool boundary.** JSON Schema keywords
   (`maxLength`, `pattern`, `enum`, `additionalProperties: false`), a typed enum
   or sealed class, runtime validation at the top of the handler, or an allowlist
   lookup — the goal is that a malformed value never reaches the handler body.
2. **Authorization runs inside the handler against the invoking principal** — not
   outsourced to the LLM's judgment, not inferred from the caller, not handled
   only by an outer framework layer. The LLM is an attacker in the threat model;
   it cannot be trusted to gate its own actions.
3. **File and path identifiers are canonicalized and verified against an explicit
   root.** Resolve the path, then check that the resolved target falls inside the
   allowed directory. Path traversal (`../`), symlink escape, and absolute-path
   injection all fail this check.
4. **Tools expose the narrowest capability that satisfies their purpose.** Read,
   write, and delete live in separate handlers, not multiplexed behind an
   `action` parameter. Narrow tools are easier to audit and harder to weaponize.
5. **Every invocation produces an audit record** containing the principal, the
   tool name, and sanitized parameters — written before the side-effecting
   operation returns.

Anchor — shape, not implementation:

```
schema: { filename: { type: string, maxLength: 128, pattern: "^[\\w-]+\\.(txt|csv)$" } }
def read_file(filename, *, caller):
    require(caller.has_permission("file:read"))
    target = (ALLOWED_ROOT / filename).resolve()
    require(target.is_relative_to(ALLOWED_ROOT))
    audit_log("read_file", caller.id, filename)
    return target.read()
```

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
