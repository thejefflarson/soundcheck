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

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **PII is redacted or pseudonymized before it reaches the model.** Replace raw
   records with opaque identifiers ("user_id=42" instead of the row), or scrub
   values matching known sensitive patterns (SSN, email, card numbers) through a
   redaction step. "Don't repeat personal details" in the prompt is not sufficient.
2. **No credentials appear in prompt strings.** Load them from environment variables
   or a secrets manager and keep them server-side — never interpolate into a system
   prompt, even "just for auth context".
3. **Every return site for the LLM response passes through an output-redaction gate**
   before the response leaves the process. This catches data that leaked through
   retrieval or memory.
4. **If the code persists conversation history or writes to a memory/vector store,**
   records are keyed or partitioned by user identity so one session's context
   cannot be retrieved by another.
5. **If prompts or completions are logged**, they go through the same redaction
   helper before emission — otherwise logs become the leak.

Anchor — shape, not implementation:

```
safe_q  = redact(user_question)
prompt  = f"Answer for user_id={user.id}: {safe_q}"     # reference, not record
raw     = call_llm(system=DEV_INSTRUCTIONS, user=prompt)
return redact(raw)                                       # every return site
```

## Verification

Confirm these properties hold for every relevant pattern present in the code under
review (each criterion applies only when its pattern is actually present):

- [ ] No PII field (SSN, DOB, email, phone, address, health record) reaches an LLM API call site without first passing through a redaction or pseudonymization step
- [ ] System prompts contain only constants loaded from a secrets-manager or environment-backed config, never hardcoded credential literals or interpolated secret values — only applies if the code references credentials (API keys, DB passwords) near the prompt construction
- [ ] Every code path that returns an LLM response to a caller routes the response through an output-redaction helper before it leaves the process
- [ ] If the code persists conversation history or writes to a memory/vector store, records are keyed or partitioned by user identity so one session's context cannot be retrieved by another — skip this criterion when the code is a stateless single-request handler with no history/memory
- [ ] If the code contains logging or telemetry statements that receive a prompt or completion variable, the variable is passed through a redaction helper before emission — skip this criterion when the code has no logging of prompts or completions

## References

- CWE-200 ([Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html))
- CWE-359 ([Exposure of Private Personal Information](https://cwe.mitre.org/data/definitions/359.html))
- [OWASP LLM06:2025 Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm06-sensitive-information-disclosure/)
