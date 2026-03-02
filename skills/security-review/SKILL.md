---
name: security-review
description: Use when the user types /security-review or explicitly requests a full
  security audit of the current code.
---

# Full Security Audit (A01:2025–A10:2025 + LLM01:2025–LLM10:2025)

## What this checks

Runs every Soundcheck skill against the code in context, producing a single
severity-ranked findings report covering all OWASP Web and LLM categories.

## Vulnerable patterns

This skill does not define its own patterns — it orchestrates the full Soundcheck
skill suite against the code in context.

## Fix immediately

1. If no file is in context, ask: "Which file(s) should I review?"
2. Invoke each Soundcheck skill in sequence:

**Web Top 10:** `soundcheck:injection` · `soundcheck:authentication-failures` ·
`soundcheck:cryptographic-failures` · `soundcheck:insecure-design` ·
`soundcheck:security-misconfiguration` · `soundcheck:supply-chain` ·
`soundcheck:integrity-failures` · `soundcheck:logging-failures` ·
`soundcheck:exceptional-conditions` · `soundcheck:broken-access-control`

**LLM Top 10:** `soundcheck:prompt-injection` · `soundcheck:sensitive-disclosure` ·
`soundcheck:llm-supply-chain` · `soundcheck:training-data-poisoning` ·
`soundcheck:model-dos` · `soundcheck:insecure-output-handling` ·
`soundcheck:insecure-plugin-design` · `soundcheck:excessive-agency` ·
`soundcheck:overreliance` · `soundcheck:model-theft`

**Additional:** `soundcheck:mcp-security` · `soundcheck:oauth-implementation` ·
`soundcheck:rag-security` · `soundcheck:insecure-local-storage` ·
`soundcheck:ipc-security` · `soundcheck:threat-modeling`

3. After all skills run, output a findings table:

```
| Severity | Skill | Finding |
|----------|-------|---------|
```

4. Rewrite all Critical and High findings using each skill's fix pattern.
5. Summarize: "X issue(s) found. Y rewritten. Z categories clean."

**When adding a new skill to Soundcheck, add it to the list in step 2 above.**

## Verification

- [ ] All skills in the list above were invoked
- [ ] Findings table produced with severity ranking
- [ ] All Critical/High findings rewritten in place

## References

- CWE-693 ([Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html))
- [OWASP Web Top 10:2025](https://owasp.org/www-project-top-ten/)
- [OWASP LLM Top 10:2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
