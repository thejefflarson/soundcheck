---
name: sensitive-disclosure
description: Use when writing code that passes sensitive data (PII, credentials, health
  data) to an LLM API, constructs system prompts containing secrets, returns LLM responses
  that could contain training data, or implements memory/context persistence.
---

# Sensitive Information Disclosure (OWASP LLM06:2025)

## What this checks

Prevents confidential data from leaking through LLM inputs or outputs. LLMs may memorize,
echo, or inference-time expose PII, credentials, and business secrets embedded in
prompts — to current users, future users, or via model extraction.

## Vulnerable patterns

- `system_prompt = f"User record: {json.dumps(user)}"` — full user object (SSN, DOB, email) in prompt
- `OPENAI_API_KEY` or DB passwords hardcoded or interpolated into system prompts
- Returning raw LLM responses that may echo back data from the system prompt
- Storing full conversation history (with PII) in shared memory/vector store across sessions

## Fix immediately

When this skill invokes, rewrite the vulnerable code using the pattern below. Explain
what was wrong and what changed. Then continue with the original task.

**Secure pattern:**

```python
import re

# Scrub PII before sending — Python
PII_PATTERNS = [
    (r"\b\d{3}-\d{2}-\d{4}\b", "[SSN]"),          # SSN
    (r"\b[\w.+-]+@[\w-]+\.\w{2,}\b", "[EMAIL]"),   # email
    (r"\b4[0-9]{12}(?:[0-9]{3})?\b", "[CC]"),       # Visa card
]

def scrub_pii(text: str) -> str:
    for pattern, label in PII_PATTERNS:
        text = re.sub(pattern, label, text)
    return text

# Pass ID references, not raw records
def build_prompt(user_id: int, question: str) -> str:
    return (
        f"Answer the following question for user_id={user_id}. "
        f"Do not repeat personal details.\n\nQuestion: {scrub_pii(question)}"
    )

# Filter LLM output before returning to caller
SENSITIVE_PATTERNS = re.compile(
    r"\b(\d{3}-\d{2}-\d{4}|[\w.+-]+@[\w-]+\.\w{2,})\b"
)

def safe_llm_response(raw: str) -> str:
    return SENSITIVE_PATTERNS.sub("[REDACTED]", raw)
```

**Why this works:** References replace raw records so the model never sees full PII.
Output scrubbing catches any data that leaked through context. No credentials should
ever appear in prompt strings — load them from environment variables and keep them
server-side only.

## Verification

After rewriting, confirm:

- [ ] No PII fields (SSN, DOB, email, phone) interpolated directly into prompt strings
- [ ] API keys and passwords come from environment variables, not prompt context
- [ ] LLM outputs pass through a PII filter before being returned to the client
- [ ] Per-user conversation history is isolated and not shared across sessions

## References

- CWE-200 ([Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html))
- CWE-359 ([Exposure of Private Personal Information](https://cwe.mitre.org/data/definitions/359.html))
- [OWASP LLM06:2025 Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm06-sensitive-information-disclosure/)
