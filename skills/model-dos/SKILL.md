---
name: model-dos
description: Use when writing LLM API call handlers, setting up inference endpoints,
  implementing chatbot backends, or configuring token limits and request throttling
  for LLM services. Also invoke when accepting user-provided prompts without length
  or complexity constraints.
---

# Model Denial of Service Security Check (OWASP LLM04:2025)

## What this checks

Protects against resource exhaustion caused by unbounded prompts, missing token caps,
or absent rate limiting. Attackers can submit enormous or recursive inputs that inflate
inference costs, saturate GPU/CPU, and deny service to legitimate users.

## Vulnerable patterns

- LLM API calls with no `max_tokens` parameter — model generates until its internal limit
- No input length validation before sending to the inference endpoint
- Multi-turn chat that accumulates context indefinitely across turns
- No per-user or per-IP rate limiting on the prompt endpoint

## Fix immediately

When this skill invokes, rewrite the vulnerable code using the pattern below. Explain
what was wrong and what changed. Then continue with the original task.

**Secure pattern:**

```python
import time
from collections import defaultdict
from openai import OpenAI

client = OpenAI()

# --- Input guards ---
MAX_INPUT_CHARS   = 8_000    # ~2 000 tokens at ~4 chars/token
MAX_CONTEXT_TURNS = 10       # cap multi-turn history
MAX_OUTPUT_TOKENS = 512      # always set; never omit

def validate_input(text: str) -> str:
    if len(text) > MAX_INPUT_CHARS:
        raise ValueError(f"Input exceeds {MAX_INPUT_CHARS} characters.")
    return text.strip()

def trim_history(messages: list[dict]) -> list[dict]:
    """Keep system message + the last MAX_CONTEXT_TURNS user/assistant pairs."""
    system = [m for m in messages if m["role"] == "system"]
    rest   = [m for m in messages if m["role"] != "system"]
    return system + rest[-(MAX_CONTEXT_TURNS * 2):]

# --- Token bucket rate limiter ---
_buckets: dict[str, tuple[float, float]] = defaultdict(lambda: (time.monotonic(), 10.0))

def check_rate_limit(user_id: str, capacity: float = 10.0, refill_rate: float = 0.5) -> None:
    last, tokens = _buckets[user_id]
    now = time.monotonic()
    tokens = min(capacity, tokens + (now - last) * refill_rate)
    if tokens < 1.0:
        raise PermissionError("Rate limit exceeded. Please wait before sending another message.")
    _buckets[user_id] = (now, tokens - 1.0)

# --- Guarded inference call ---
def call_llm(user_id: str, user_text: str, history: list[dict]) -> str:
    check_rate_limit(user_id)
    safe_text = validate_input(user_text)
    history = trim_history(history)
    history.append({"role": "user", "content": safe_text})

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=history,
        max_tokens=MAX_OUTPUT_TOKENS,   # always set
        timeout=30,                     # fail fast; never block indefinitely
    )
    return response.choices[0].message.content
```

**Why this works:** Input length validation stops oversized payloads before they reach
the API. `max_tokens` and `timeout` bound both cost and wall-clock time per request.
The token bucket rate limiter prevents a single user from monopolizing the endpoint.

## Verification

After rewriting, confirm:

- [ ] Every LLM API call sets `max_tokens` (or equivalent) explicitly
- [ ] User input length is validated before the API call, not after
- [ ] Multi-turn context is capped and trimmed, not grown without bound
- [ ] Per-user rate limiting is applied at the endpoint layer
- [ ] A request timeout is set so hung inference calls do not block threads indefinitely

## References

- CWE-400 ([Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html))
- CWE-770 ([Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html))
- [OWASP LLM04:2025 Model Denial of Service](https://genai.owasp.org/llmrisk/llm04-model-denial-of-service/)
