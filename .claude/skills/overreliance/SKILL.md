---
name: overreliance
description: Use when writing code that displays LLM output as authoritative fact,
  uses LLM decisions to gate consequential outcomes without human review, or builds
  automated pipelines where LLM judgment drives downstream actions.
---

# Overreliance on LLM Output (OWASP LLM09:2025)

## What this checks

Prevents systems from treating LLM output as ground truth. LLMs hallucinate, produce
confident-sounding errors, and lack real-time knowledge. Acting on unverified output
in medical, legal, financial, or deployment contexts can cause serious harm.

## Vulnerable patterns

- Displaying LLM diagnosis or legal advice directly in UI with no caveat
- Automated pipeline merges or deploys code based solely on LLM code-review approval
- LLM confidence score ignored — any non-null response accepted as correct
- No fallback path when LLM output fails a sanity check or confidence threshold

## Fix immediately

When this skill invokes, flag the vulnerable code and explain the risk. Then suggest a
fix that establishes these properties:

1. **Gate on confidence and domain, and the gate must branch.** Defining
   `CONFIDENCE_THRESHOLD` or a `HIGH_STAKES_DOMAINS` set without a conditional that
   actually diverges behavior (review queue vs. direct return / proceed vs. halt) is
   the exact bug this skill prevents. The failing branch routes to human review; the
   passing branch attaches a disclaimer and returns.
2. **No raw model output reaches the caller.** Every return site wraps the content
   with an "AI-generated — verify before acting" disclaimer.
3. **Irreversible actions (merge, deploy, payment, publish) require a human trigger**
   — they are never invoked from the function that consumes the LLM result.
4. **Audit log captures enough context to reconstruct the decision**: the inputs the
   LLM saw, the output it produced, and the confidence signal. Metadata alone
   (request id, timestamp, domain) is insufficient — a reviewer cannot second-guess
   a decision they can't re-read.

Anchor (Python, any language works the same way):

```
if confidence < THRESHOLD or domain in HIGH_STAKES:
    audit_log(prompt, content, confidence)   # enough to reconstruct the call
    return route_to_human_review(content + DISCLAIMER)
return content + DISCLAIMER                  # no raw output; disclaimer on every path
```

## Verification

Confirm these properties hold (language-agnostic; apply only where the pattern is
present):

- [ ] Every return site that emits LLM-generated content attaches a disclaimer or equivalent "AI-generated" marker — no path emits raw model output
- [ ] A confidence signal is compared against a named threshold in a conditional whose branches diverge (human-review path vs. direct return, or halt vs. proceed). Threshold constants that are defined but never branched on do not satisfy this
- [ ] High-stakes domains are checked against an explicit list before any automated action, and the failing branch routes to human review rather than returning LLM output
- [ ] Irreversible downstream actions (merge, deploy, payment, publish) are invoked only from a function separate from the one consuming the LLM result
- [ ] Audit-log call sites record sufficient context to reconstruct the decision — at minimum the LLM's input, its output, and the confidence signal. Logging only metadata is not enough

## References

- CWE-1021 ([Improper Restriction of Rendered UI Layers](https://cwe.mitre.org/data/definitions/1021.html))
- [OWASP LLM09:2025 Overreliance](https://genai.owasp.org/llmrisk/llm09-overreliance-on-llm-output/)
