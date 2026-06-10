---
name: contract-review
description: Deep review that audits API contracts for mismatches between what callers assume and what implementations enforce. Designed for nightly CI, pre-release scans, or manual deep audits — runs in tens of minutes, not seconds. Surfaces bugs that single-pass OWASP review misses — caller/callee invariant gaps, trust-anchor confusion, predicate misnaming.
---

# Contract Review (deep) (A04:2025)

## What this checks

Bugs that only resolve across both sides of a contract — a helper
whose body guarantees less than callers assume. `security-review`
pattern-matches 45 OWASP/LLM categories; this exists for what that
misses. Nightly CI or manual audits; not per-PR.

## Vulnerable patterns

Deliberately none. Pattern lists bias the search; `contract-audit`
uses one open question per hotspot — *what does the caller assume
that the body doesn't enforce?* — and the orchestrator does not
inspect code.

## Procedure

Use the **Agent** tool to dispatch subagents. Don't audit yourself.
Keep state in conversation memory; don't write files.

### Stage 0 — Threat model

Dispatch one `threat-modeling` subagent. Keep its JSON in
conversation context; thread it into every later subagent.

### Stage 1 — Hotspot seed

Dispatch one `hotspot-mapping` subagent with the threat model
JSON. It scans the whole repo and returns a list of
`{file, lines, name, category, priority, why}` entries —
interesting functions to audit. Keep that list in conversation
memory.

### Stage 2 — Round loop

Track two things in conversation memory:

- `probed`: a mapping from hotspot key to the count of prior rounds
- `refuted[hotspot]`: per-hotspot list of REFUTED `(impl, caller,
  gap)` triples from prior rounds

While stop conditions not met:

1. **Pick** the hotspot with the fewest entries in `probed`
   (ties: order in the seed list).
2. **Dispatch one `contract-audit` subagent** with the threat model
   JSON, `Hotspot:`, `Why:`, `Round:`, and the `refuted[hotspot]`
   block. The threat model informs reachability of the caller path
   (untrusted-input-reachable → real severity; trusted-only → Low).
3. **Parse the `<soundcheck-contract>` trailer.** Append every
   VERIFIED hypothesis to an in-memory `findings` list, **copying
   every field verbatim** (including `guards_traced` and any other
   fields the auditor emitted), and adding `hotspot_key` and
   `round` annotations. Append every REFUTED to `refuted[hotspot]`.
4. Increment `probed[hotspot]`.
5. **Update stagnation counter.** Reset on VERIFIED; else increment.

Stop conditions (in priority order):

- `rounds_done >= max_rounds`
- wall-clock > `max_hours`
- stagnation ≥ `stagnation_limit`
- every hotspot has emitted `reason: exhausted` once

### Stage 3 — Render

**Primary output is a human Markdown report.** JSON blocks are a
machine-readable trailer — NOT a substitute for prose. Emit in order:

1. `# Contract Review` heading.
2. **Findings table** sorted by severity (Critical → Low):
   `| Severity | Impl | Caller | Gap | Trigger |`. Zero findings:
   skip the table; write `No contract gaps found across N hotspots,
   R rounds.`
3. **Per-finding details** — one `### <Severity>: <impl> ↔ <caller>`
   heading each, then `gap`, `trigger`, and a short `guards_traced`
   summary as prose. This is what reviewers actually read.
4. **Summary line:** `N findings across M hotspots, R rounds
   (stopped: <reason>).`
5. **JSON trailer** in two tagged blocks (required even when empty):

```
<soundcheck-contract>
[{"severity":"Critical|High|Medium|Low",
  "impl":"<file>:<line>","caller":"<file>:<line>",
  "gap":"<one-sentence divergence>",
  "trigger":"<2–4 line attacker scenario>",
  "guards_traced":[...],
  "hotspot_key":"<key>","round":N}]
</soundcheck-contract>

<soundcheck-contract-summary>
{"rounds":R,"verified":N,"hotspots_probed":M,
 "stopped":"max_rounds|max_hours|stagnation|exhausted"}
</soundcheck-contract-summary>
```

## Verification

- [ ] Markdown findings table is rendered BEFORE the JSON blocks
      (the prose is the primary output)
- [ ] Per-finding details section is present (one heading per finding)
- [ ] Every row in the findings table corresponds to one entry in
      the `<soundcheck-contract>` JSON array
- [ ] Every JSON entry has `severity`, `impl`, `caller`, `gap`,
      `trigger`, `hotspot_key`, `round`
- [ ] `<soundcheck-contract>` is always present, even when empty
      (`[]`); same for `<soundcheck-contract-summary>`
- [ ] No files written; output is the prose + two tagged blocks

## References

- CWE-435 ([Improper Interaction Between Multiple Correctly-Behaving Entities](https://cwe.mitre.org/data/definitions/435.html))
- CWE-345 ([Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html))
- CWE-820 ([Missing Synchronization](https://cwe.mitre.org/data/definitions/820.html))
- [OWASP A04:2025 — Insecure Design](https://owasp.org/www-project-top-ten/)
