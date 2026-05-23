---
name: contract-review
description: Deep review that audits API contracts for mismatches between what callers assume and what implementations enforce. Designed for nightly CI, pre-release scans, or manual deep audits — runs in tens of minutes, not seconds. Surfaces bugs that single-pass OWASP review misses — caller/callee invariant gaps, trust-anchor confusion, predicate misnaming.
---

# Contract Review (deep) (A04:2025)

## What this checks

Bugs whose vulnerability only resolves across both sides of a
contract — a helper whose body guarantees less than its callers
assume. `security-review` pattern-matches 45 OWASP/LLM categories;
this exists for what that misses. Fine for nightly CI or manual
audits; not for per-PR review.

## Vulnerable patterns

Deliberately none. Pattern lists bias the search; `contract-audit`
uses one open question per hotspot — *what does the caller assume
that the body doesn't enforce?* — and the orchestrator (this skill)
does not inspect code itself.

## Procedure

Use the **Agent** tool to dispatch subagents. Do not audit code
yourself — subagents read, you orchestrate. Keep all state in
conversation memory; do not write files. The findings table you
emit at the end *is* the output.

### Stage 0 — Threat model

Dispatch one `threat-modeling` subagent. Keep its JSON in
conversation context; thread it into every later subagent.

### Stage 1 — Hotspot seed

Dispatch one `hotspot-mapping` subagent with `Focus:`:

> Contract review. Emit two classes, in order:
> (1) **Every public API entry point**, unconditionally — syscalls,
> exported library symbols, HTTP/RPC handlers, CLI subcommands,
> message-queue consumers. Their callers are outside the repo, so
> caller-count is not a filter.
> (2) **Internal helpers with ≥2 in-repo callers** on a
> security-relevant path. Do not skip a function for looking routine.

Drop the `skill` field from the response; you now have a hotspot
list in conversation memory.

### Stage 2 — Round loop

Track two things in conversation memory:

- `probed`: a mapping from hotspot key to the count of prior rounds
- `refuted[hotspot]`: per-hotspot list of REFUTED `(impl, caller,
  gap)` triples from prior rounds

While stop conditions not met:

1. **Pick** the hotspot with the fewest entries in `probed`
   (ties: order in the seed list).
2. **Dispatch one `contract-audit` subagent** with `Hotspot:`,
   `Why:`, `Round:`, and the `refuted[hotspot]` block.
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

Emit two outputs.

First, a Markdown table sorted by severity (Critical → Low) for
humans:

| Severity | Impl | Caller | Gap | Trigger |

Then one summary line.

Then the machine-readable JSON, in two tagged blocks. **Both blocks
are required, even if `findings` is empty.**

```
<soundcheck-contract>
[
  {"severity": "Critical | High | Medium | Low",
   "impl": "<file>:<line>", "caller": "<file>:<line>",
   "gap": "<one-sentence divergence>",
   "trigger": "<2–4 line concrete attacker scenario>",
   "guards_traced": [ ...verbatim from contract-audit... ],
   "hotspot_key": "<key>", "round": N}
]
</soundcheck-contract>

<soundcheck-contract-summary>
{"rounds": R, "verified": N, "hotspots_probed": M,
 "stopped": "max_rounds | max_hours | stagnation | exhausted"}
</soundcheck-contract-summary>
```

Mirrors `<soundcheck-findings>` from `security-review` so downstream
tooling can parse both modes the same way.

## Verification

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
