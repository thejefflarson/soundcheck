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

## Fix immediately

When this skill invokes, rewrite the vulnerable code using the pattern below. Explain
what was wrong and what changed. Then continue with the original task.

**Secure pattern:**

```python
import re

DISALLOWED = re.compile(
    r"(ignore previous|disregard|new instruction|system prompt|forget)", re.I
)

def sanitize_user_input(text: str, max_chars: int = 2000) -> str:
    text = text[:max_chars].strip()
    if DISALLOWED.search(text):
        raise ValueError("Input contains disallowed instruction patterns.")
    return text

def build_messages(system_instructions: str, user_input: str, docs: list[str]) -> list[dict]:
    safe_input = sanitize_user_input(user_input)
    context_block = "\n---\n".join(docs)  # retrieved RAG content

    return [
        {"role": "system", "content": system_instructions},          # developer-controlled only
        {"role": "user",   "content": (
            f"<context>\n{context_block}\n</context>\n\n"            # data tier, clearly delimited
            f"<question>\n{safe_input}\n</question>"                 # user tier, clearly delimited
        )},
    ]

# Output validation gate — reject responses that echo injection markers
def validate_llm_output(response: str) -> str:
    if DISALLOWED.search(response):
        raise ValueError("LLM response contains suspicious instruction language.")
    return response
```

**Why this works:** Structural role separation prevents user text from overriding system
instructions. XML delimiters make the data/instruction boundary legible to the model.
The input and output validation gates catch known injection phrases before they are
acted on.

## Verification

After rewriting, confirm:

- [ ] User input never appears in the `system` role message
- [ ] Retrieved documents are wrapped in explicit delimiter tags, not concatenated raw
- [ ] Input length and pattern validation runs before the API call
- [ ] LLM output is validated before it triggers any downstream action

## References

- CWE-77 ([Improper Neutralization of Special Elements in a Command](https://cwe.mitre.org/data/definitions/77.html))
- CWE-74 ([Improper Neutralization of Special Elements in Output](https://cwe.mitre.org/data/definitions/74.html))
- [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
