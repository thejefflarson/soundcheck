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

MAX_INPUT_CHARS   = 8_000
MAX_CONTEXT_TURNS = 10
MAX_OUTPUT_TOKENS = 512

_buckets: dict = defaultdict(lambda: (time.monotonic(), 10.0))

def check_rate_limit(user_id: str) -> None:
    last, tokens = _buckets[user_id]
    now = time.monotonic()
    tokens = min(10.0, tokens + (now - last) * 0.5)
    if tokens < 1.0:
        raise PermissionError("Rate limit exceeded.")
    _buckets[user_id] = (now, tokens - 1.0)

def call_llm(user_id: str, user_text: str, history: list[dict]) -> str:
    check_rate_limit(user_id)
    if len(user_text) > MAX_INPUT_CHARS:
        raise ValueError(f"Input exceeds {MAX_INPUT_CHARS} chars")
    system = [m for m in history if m["role"] == "system"]
    trimmed = system + [m for m in history if m["role"] != "system"][-(MAX_CONTEXT_TURNS * 2):]
    trimmed.append({"role": "user", "content": user_text.strip()})
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=trimmed,
        max_tokens=MAX_OUTPUT_TOKENS,
        timeout=30,
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
