---
name: security-cleanup
description: Use when the user wants to fix security issues found by /security-review
  or when they ask to clean up, remediate, or apply fixes for security findings.
---

# Security Cleanup (A01:2025–A10:2025 + LLM01:2025–LLM10:2025)

## What this checks

Applies fixes for security findings identified by `/security-review` or
another Soundcheck skill. Works through findings one at a time, showing
the proposed fix and waiting for confirmation before editing.

## Vulnerable patterns

This skill does not detect vulnerabilities — it remediates them. Use
`/security-review` first to produce the findings.

## Procedure

1. If the user provides a findings table or references a recent
   `/security-review`, use those findings. Otherwise, ask the user to
   run `/security-review` first or paste the findings they want fixed.

2. For each finding (highest severity first):
   - Read the cited file at the cited line
   - Show the current vulnerable code
   - Show the proposed fix with a brief explanation
   - Ask: "Apply this fix?" — wait for confirmation
   - On yes: Edit the file. On no: skip and move to the next finding.

3. After all findings are processed, summarize what was fixed and what
   was skipped.

**Fix quality rules:**
- Read the relevant Soundcheck skill at `.claude/skills/<skill>/SKILL.md`
  for the correct fix pattern before proposing a change
- Use the language's idiomatic safe API (e.g. Go `html/template` not
  `text/template`, Python `Environment(autoescape=True)` not
  `select_autoescape`, Java `PreparedStatement` not `Statement`)
- Never introduce a fix that changes the code's observable behavior
  beyond removing the vulnerability
- If unsure about the correct fix, say so and ask the developer

## Verification

- [ ] Every fix was confirmed by the user before applying
- [ ] Each fix addresses the specific finding cited
- [ ] No fix introduces new vulnerabilities or changes business logic
- [ ] Summary lists all findings and their disposition (fixed/skipped)

## References

- CWE-693 ([Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html))
- [OWASP Web Top 10:2025](https://owasp.org/www-project-top-ten/)
- [OWASP LLM Top 10:2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
