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

When this skill invokes, flag the vulnerable code and explain the risk. Show the secure pattern below as a suggested fix. Then continue with the original task.

**Critical:** The confidence threshold and high-stakes domain list MUST appear in an
`if/else` branch that actually diverges behavior — defining them as constants without
branching on them is the exact bug this skill prevents. If the rewrite defines
`CONFIDENCE_THRESHOLD` or `HIGH_STAKES_DOMAINS` but never uses them in a conditional,
the rewrite is still vulnerable.

**Secure pattern:**

```python
from dataclasses import dataclass

HIGH_STAKES_DOMAINS = {"medical", "legal", "financial", "deployment"}
CONFIDENCE_THRESHOLD = 0.80

@dataclass
class LLMResult:
    prompt: str         # original prompt/input MUST be captured for audit
    content: str
    confidence: float   # 0.0–1.0; derive from logprobs or a self-eval prompt
    domain: str

DISCLAIMER = (
    "\n\n---\n_AI-generated content. Verify with a qualified professional "
    "before acting on this information._"
)

def audit_log_for_review(result: LLMResult) -> None:
    # All three pieces — prompt, content, confidence — must reach the log.
    logger.info("llm_review", extra={
        "prompt": result.prompt, "content": result.content,
        "confidence": result.confidence, "domain": result.domain,
    })

def present_llm_result(result: LLMResult) -> dict:
    requires_review = (result.domain in HIGH_STAKES_DOMAINS
                       or result.confidence < CONFIDENCE_THRESHOLD)
    status = "pending_review" if requires_review else "ai_generated"
    if requires_review:
        audit_log_for_review(result)
    # Every return site attaches DISCLAIMER — no raw output reaches callers.
    return {"content": result.content + DISCLAIMER,
            "status": status, "confidence": result.confidence}

# High-stakes pipelines branch on confidence too, then halt for human review.
def review_and_maybe_merge(pr_id: int, r: LLMResult) -> None:
    audit_log_for_review(r)
    if r.confidence < CONFIDENCE_THRESHOLD:
        notify_human_reviewer(pr_id, r.content + DISCLAIMER); return
    notify_human_reviewer(pr_id, r.content + DISCLAIMER)
```

**Why this works:** Confidence gating routes low-certainty or high-stakes output to
human review rather than direct presentation. Disclaimers set accurate user expectations.
Irreversible pipeline steps (merge, deploy) always require a separate human trigger.

## Verification

Confirm the following *properties* hold (language-agnostic):

- [ ] Every code path that returns or renders LLM-generated content to a user concatenates, wraps, or otherwise attaches an "AI-generated" disclaimer string — no user-facing return site emits raw model output
- [ ] A confidence value is compared against a named threshold constant in a conditional expression whose branches actually diverge (review queue vs. direct return / proceed vs. halt) — defining the threshold without a branching comparison does not satisfy this property
- [ ] High-stakes domains (medical, legal, financial, deployment, or equivalent) are checked against an explicit allowlist/denylist before any automated action, and the failing branch routes to a human-review path rather than returning the LLM output directly
- [ ] Irreversible downstream actions (merge, deploy, payment, publish) are never invoked from the same function that consumes the LLM result — they require a separate human-triggered entry point
- [ ] The audit log call site receives and records all of: the original inputs to the LLM, the LLM output content, and the confidence value — logging only metadata (domain, timestamp, request id) does not satisfy this property

## References

- CWE-1021 ([Improper Restriction of Rendered UI Layers](https://cwe.mitre.org/data/definitions/1021.html))
- [OWASP LLM09:2025 Overreliance](https://genai.owasp.org/llmrisk/llm09-overreliance-on-llm-output/)
