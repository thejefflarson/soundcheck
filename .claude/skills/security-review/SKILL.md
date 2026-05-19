---
name: security-review
description: Runs a full OWASP/CWE security audit via isolated subagents. Use when the user
  types /security-review or explicitly requests a full security audit of the
  current code.
---

# Full Security Audit (A01:2025–A10:2025 + LLM01:2025–LLM10:2025)

## What this checks

Full audit via isolated subagents. Main context shows only findings.

## Vulnerable patterns

Delegates to the Soundcheck `vulnerability-audit` subagent, which
applies the per-category skills (`injection`, `csrf`, `ssrf`, …).

## Procedure

Use the **Agent** tool plus **one** Glob call (for Stage 1 dir
enumeration). **No Read/Grep/Bash in main context.** Stage prompts
live in `agents/`: `threat-modeling`, `hotspot-mapping`,
`design-review`, `vulnerability-audit`, `attack-chain-analysis`.
This skill is just the coordinator.

Copy this checklist as you progress:

```
- [ ] Stage 0 — threat-modeling returned
- [ ] Stage 1 — hotspot-mapping batches dispatched and returned
- [ ] Stages 1b+2 — design-review + N vulnerability-audit in ONE message
- [ ] Stage 3 — attack-chain-analysis returned
- [ ] Stage 4 — findings table rendered with severity legend
- [ ] Stage 5 — suggested /security-cleanup to the user
```

### Stage 0 — Threat model

Dispatch one `threat-modeling` subagent. It returns JSON describing
purpose, deployment, trusted/untrusted inputs, attack surface, and
out-of-scope. Thread this JSON into every later subagent.

### Stage 1 — Hotspot map (batched fan-out)

**Glob `*/` and `*/*/`** to enumerate the top two directory levels
of the whole repo — not just `attack_surface`, which Stage 0 often
under-enumerates. Drop paths under `out_of_scope` and standard
boilerplate (`node_modules`, `.venv`, `venv`, `dist`, `build`,
`target`, `.git`, `vendor`, `__pycache__`, `.next`, `coverage`,
`migrations`, `fixtures`, `tests`, `test`, `docs`). Dedupe. Don't
filter by extension — language-agnostic.

Split into batches of 5. **In a SINGLE message**, dispatch one
`hotspot-mapping` per batch with the threat model JSON and
`Focus: <comma-separated dirs>`. No cap on batches — scales with
repo size. Concatenate, dedupe by `(file, lines)`.

### Stages 1b + 2 — Design review and vulnerability audit (parallel)

**In a SINGLE message**, dispatch:

- One `design-review` subagent with the threat model.
- One `vulnerability-audit` subagent per chunk of ≤5 hotspots. Every
  hotspot must be in some chunk; serial launches defeat parallelism.

Concatenate every returned findings array. Dedupe by `(file, line)`.

### Stage 3 — Attack-chain analysis

Dispatch one `attack-chain-analysis` subagent with the merged
findings. It returns chain objects with plain-English narratives, or
`[]`.

### Stage 4 — Render

Emit `# Security Review`, then the legend *Critical = anyone on the
internet can exploit. High = needs an account. Medium = limited blast
radius. Low = defense-in-depth.* Then a findings table:
**Severity / Where / What's wrong / How to fix** (use the auditor's
`finding`/`fix` verbatim; append `(category: <skill>)` to *What's
wrong*). If chains exist, emit `## Attack chains` with
`### Chain N — <effective_severity>` per chain and the narrative as
prose. One summary line. Zero findings: `Security review complete.
No findings across N hotspots.`

### Stage 5 — Cleanup

After rendering, suggest running `/security-cleanup` to apply fixes
interactively. Do not auto-rewrite files.

## Verification

- [ ] Every vulnerability has a finding with `severity`, `file:line`, OWASP/CWE category, and a concrete fix
- [ ] `finding`/`fix` text is plain language a non-security developer can act on
- [ ] Response ends with a summary line

## References

- CWE-693 ([Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html))
- [OWASP Web Top 10:2025](https://owasp.org/www-project-top-ten/)
- [OWASP LLM Top 10:2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
