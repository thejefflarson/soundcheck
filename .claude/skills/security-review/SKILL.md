---
name: security-review
description: Use when the user types /security-review or explicitly requests a full
  security audit of the current code.
---

# Full Security Audit (A01:2025–A10:2025 + LLM01:2025–LLM10:2025)

## What this checks

Full audit via isolated subagents. Main context shows only findings.

## Vulnerable patterns

Delegates to subagents applying the Soundcheck skill suite.

## Procedure

Use the **Agent** tool. **Main loop ONLY dispatches Agent calls and merges
JSON — never Read/Grep/Glob/Bash in main context. All inspection happens
in subagents.**

### Skill catalog (auditors must name one of these)

`injection`, `prompt-injection`, `insecure-output-handling`, `token-smuggling`,
`authentication-failures`, `oauth-implementation`, `broken-access-control`,
`integrity-failures`, `insecure-local-storage`, `cryptographic-failures`,
`security-misconfiguration`, `supply-chain`, `rag-security`,
`exceptional-conditions`, `logging-failures`, `ipc-security`,
`sensitive-disclosure`, `model-theft`, `model-dos`, `mcp-security`,
`excessive-agency`, `multi-agent-trust`, `overreliance`,
`insecure-plugin-design`, `llm-supply-chain`, `insecure-design`.

### Stage 0 — Threat model (one subagent)

Launch a `general-purpose` subagent:

> "Read `CLAUDE.md`, `README.md`, top-level structure. Return ONLY JSON
> `{purpose, deployment, trusted_inputs, untrusted_inputs, attack_surface,
> out_of_scope}`. `out_of_scope` = finding categories to discount."

Thread `<threat_model>` into every later subagent.

### Stage 1 — Hotspot map (one subagent)

Launch with skill catalog + threat model:

> "Threat model: `<threat_model>`. Glob common source extensions; skip
> `node_modules`, `.venv`, `dist`, `build`, `target`. Focus on
> `attack_surface`. **Be exhaustive** — list every Critical/High
> security-sensitive area you can find; do not self-limit. Assign each
> a `skill`. Return ONLY `[{category, skill, file, lines, what}, ...]`."

### Stage 1b — Design review (parallel with Stage 2)

Auditors pattern-match existing code; this stage finds *missing* controls
(no timeout, no cost cap, prose-only guard):

> "Threat model: `<threat_model>`. Read
> `.claude/skills/threat-model/SKILL.md`; apply its checklist to every
> file in `attack_surface`. For each missing control, emit
> `{severity, file, line, skill, finding, fix}`. Use `insecure-design`
> for generic gaps. `[]` if none."

Merge output with Stage 2's before Stage 3.

### Stage 2 — Auditors (parallel subagents)

Chunks of ≤5 hotspots. **Emit ALL auditor Agent calls in ONE message**
(serial launches defeat the purpose — every hotspot must be covered by
some chunk). Each gets:

> "Threat model: `<threat_model>`. Audit hotspots `<chunk JSON>`. For
> each, open the cited file and apply its named skill — read
> `.claude/skills/<skill>/SKILL.md`, match against
> `## Vulnerable patterns`. Include Critical/High/Medium/Low, but
> discount `out_of_scope` and trust `trusted_inputs`. Return ONLY
> `[{severity, file, line, skill, finding, fix}]`, omitting clean and
> out-of-scope. `[]` if nothing."

Concatenate all returned arrays. Dedupe by `(file, line)`.

### Stage 3 — Attack-chain analysis (one subagent)

> "Given findings `<merged>`, find chains where one finding enables
> another. Verify reachability via Read/Grep. Return ONLY
> `[{chain_id, finding_ids, narrative, effective_severity, attacker_flow},
> ...]`. Empty if none."

### Stage 4 — Render

Emit `# Security Review`, findings table (severity/file:line/skill/
finding/fix), optional `## Attack chains` with attacker flow in plain
English. One summary line. Zero findings: `Security review complete.
No findings across N hotspots.`

### Stage 5 — Cleanup

After rendering, suggest running `/security-cleanup` to apply fixes
interactively. Do not auto-rewrite files.

## Verification

- [ ] For every vulnerability present in the input, a corresponding finding is identified
- [ ] Each finding names the relevant OWASP category or CWE
- [ ] For every finding, a concrete fix (code rewrite or specific remediation step) is provided
- [ ] Findings reference source locations (function name, line, or code snippet)
- [ ] Response includes a summary or severity assessment of the findings

## References

- CWE-693 ([Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html))
- [OWASP Web Top 10:2025](https://owasp.org/www-project-top-ten/)
- [OWASP LLM Top 10:2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
