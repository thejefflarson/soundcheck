---
name: multi-agent-trust
description: Use when writing code that calls other agents, spawns subagents, builds
  multi-agent pipelines, or passes messages between LLM agents. Also invoke when an
  orchestrator delegates tasks to worker agents or when agents share tools and permissions.
---

# Multi-Agent Trust Boundaries (LLM08:2025)

## What this checks

Detects agent-to-agent calls that lack authentication, authorization, or permission
scoping. When agents blindly trust messages from other agents, a compromised or
malicious agent can hijack the entire pipeline.

## Vulnerable patterns

- `requests.post("http://worker/run", json={"task": task})` — inter-agent call with no auth token
- Worker agent initialized with the orchestrator's full API key and tool scope
- Agent output passed directly as input to the next agent without schema validation
- No verification that a message claiming to be from "agent-A" is actually from agent-A

## Fix immediately

- **Auth between agents**: require a shared secret or signed JWT on every agent-to-agent call, verified by the receiver before processing
- **Scope permissions down**: each agent receives only the tools and credentials it needs — never the orchestrator's full set
- **Validate agent messages**: treat messages from other agents like untrusted user input — validate schema, reject unexpected fields

```python
# Orchestrator: include auth header on every inter-agent call
resp = requests.post(
    "http://worker/run",
    json={"task": task},
    headers={"Authorization": f"Bearer {AGENT_SECRET}"},
)

# Worker: reject calls missing a valid token
if request.headers.get("Authorization") != f"Bearer {AGENT_SECRET}":
    return jsonify({"error": "unauthorized"}), 401
```

Rewrite the vulnerable call site in place, explain what changed, then continue.

## Verification

- [ ] Every agent-to-agent call includes an auth token verified by the receiver
- [ ] Each agent is initialized with the minimum permissions needed for its task
- [ ] Messages received from other agents are validated against a schema before use
- [ ] No agent blindly executes instructions received from another agent

## References

- CWE-306 ([Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html))
- CWE-272 ([Least Privilege Violation](https://cwe.mitre.org/data/definitions/272.html))
- [OWASP LLM08:2025 Excessive Agency](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP Agentic AI Top 10:2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
