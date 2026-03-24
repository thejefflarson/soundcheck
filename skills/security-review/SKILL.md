---
name: security-review
description: Use when the user types /security-review or explicitly requests a full
  security audit of the current code.
---

# Full Security Audit (A01:2025–A10:2025 + LLM01:2025–LLM10:2025)

## What this checks

Orchestrates the Soundcheck skill suite, producing a severity-ranked findings report.

## Vulnerable patterns

This skill does not define its own patterns — it orchestrates other Soundcheck skills.

## Fix immediately

1. Glob all source files (`**/*.py`, `**/*.js`, `**/*.ts`, `**/*.go`, `**/*.java`,
   `**/*.rb`, `**/*.php`, `**/*.cs`, `**/*.rs`). Skip `node_modules/`, `.venv/`,
   `dist/`, `build/`. Read each file; prioritize auth, I/O, and config for large repos.

2. Based on what you read, invoke only relevant skills; skip any whose category is absent.

   - `soundcheck:injection` — SQL, shell, templates, eval with user input
   - `soundcheck:authentication-failures` — login, sessions, passwords, MFA, API keys
   - `soundcheck:cryptographic-failures` — encryption, hashing, RNG, TLS
   - `soundcheck:security-misconfiguration` — server config, CORS, debug flags, headers
   - `soundcheck:supply-chain` — package manifests, dependency pinning, CI/CD
   - `soundcheck:integrity-failures`
   - `soundcheck:logging-failures`
   - `soundcheck:exceptional-conditions`
   - `soundcheck:broken-access-control` — authorization, ownership, IDOR
   - `soundcheck:insecure-design` — rate limiting, business logic, state changes
   - `soundcheck:prompt-injection` — LLM prompts with user or external input
   - `soundcheck:sensitive-disclosure` — PII or credentials in LLM context
   - `soundcheck:llm-supply-chain` — loading or downloading pre-trained models
   - `soundcheck:training-data-poisoning` — fine-tuning pipelines, dataset ingestion
   - `soundcheck:model-dos` — LLM endpoints with unbounded user prompts
   - `soundcheck:insecure-output-handling` — rendering or executing LLM output
   - `soundcheck:insecure-plugin-design` — LLM tool/function definitions
   - `soundcheck:excessive-agency` — autonomous agents, LLM-triggered real-world actions
   - `soundcheck:overreliance`
   - `soundcheck:model-theft`
   - `soundcheck:mcp-security` — MCP server definitions, tool handlers
   - `soundcheck:oauth-implementation` — OAuth2/OIDC flows, JWT validation
   - `soundcheck:rag-security` — RAG pipelines, vector stores, doc retrieval
   - `soundcheck:insecure-local-storage` — plaintext secrets in local files or platform stores
   - `soundcheck:ipc-security` — URL schemes, Android intents, XPC, IPC sockets
   - `soundcheck:threat-model` — new endpoints, pipelines, trust boundary changes
   - `soundcheck:multi-agent-trust` — agent-to-agent auth, permission scoping, message validation
   - `soundcheck:token-smuggling` — Unicode normalization, RTL override, homoglyph bypass

3. Output a findings table:

   | Severity | Skill | Finding |
   |----------|-------|---------|

4. Rewrite all Critical and High findings using each skill's fix pattern.
5. Summarize with a full inventory: list each skill invoked and each skill skipped by name.
   Example: "Skills invoked: injection, authentication-failures, supply-chain. Skipped (not applicable): prompt-injection, model-dos, llm-supply-chain, ..."

## Verification

- [ ] Only relevant skills invoked; skipped skills noted
- [ ] Findings table produced with severity ranking
- [ ] All Critical/High findings rewritten in place

## References

- CWE-693 ([Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html))
- [OWASP Web Top 10:2025](https://owasp.org/www-project-top-ten/)
- [OWASP LLM Top 10:2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
