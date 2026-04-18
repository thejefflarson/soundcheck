---
name: prompt-injection
description: Use when writing code that constructs LLM prompts from user input, builds
  system prompts, implements RAG pipelines, or processes external documents fed to a
  model. Also invoke when external data can influence LLM context.
---

# Prompt Injection Security Check (OWASP LLM01:2025)

## What this checks

Protects against attacker-controlled text that hijacks LLM instructions. Direct
injection arrives through user input; indirect injection arrives through retrieved
documents, emails, or tool outputs. Both can cause the model to exfiltrate data,
bypass guardrails, or execute unintended actions.

## Vulnerable patterns

- `f"You are a helpful assistant. Answer: {user_input}"` — user text lands in the instruction tier
- Concatenating retrieved RAG documents directly into the system prompt
- Passing raw email or document content into a prompt with no boundary markers
- No separation between developer instructions and untrusted data
- Returning a raw model response to the caller or into a downstream action with no validation

## Fix immediately

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **Trust tiers are structurally separate.** Developer instructions go in the
   `system` role; user input and retrieved documents go in the `user` role wrapped
   in explicit delimiter tags (`<context>…</context>`, `<question>…</question>`).
   Never interpolate user text into the system prompt.
2. **Input is bounded and screened before the API call.** Apply a length cap and
   reject obvious injection markers (e.g. phrases like "ignore previous",
   "new instruction"). Screening is a denylist and will not catch everything, but
   it raises the bar.
3. **Output is validated before any downstream action.** Every code path that uses
   the model's response — returning it to the caller, rendering it, logging it,
   triggering a tool call — first routes it through a gate that enforces size
   bounds and rejects suspicious instruction language. A defined validator that
   is never called does not satisfy this.

Anchor — any language works the same way:

```
system:  developer_instructions            # no user text here
user:    <context>{docs}</context>         # delimited, from the data tier
         <question>{sanitized_input}</question>

raw   = call_llm(messages)
safe  = validate_llm_output(raw)           # gate before ANY downstream use
return safe
```

## Verification

Confirm these properties hold:

- [ ] User input never appears in the `system` role message
- [ ] Retrieved documents are wrapped in explicit delimiter tags, not concatenated raw into the prompt
- [ ] Input length and pattern validation runs before the API call
- [ ] The LLM response passes through a validation step at every call site before it is returned, rendered, logged, or used to trigger an action. A validator defined but never invoked does not count.

## References

- CWE-77 ([Improper Neutralization of Special Elements in a Command](https://cwe.mitre.org/data/definitions/77.html))
- CWE-74 ([Improper Neutralization of Special Elements in Output](https://cwe.mitre.org/data/definitions/74.html))
- [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
