---
name: model-theft
description: Use when writing inference API endpoints, deploying LLM-serving infrastructure,
  implementing model access controls, or configuring rate limiting and authentication
  for model endpoints.
---

# Model Theft (OWASP LLM10:2025)

## What this checks

Prevents unauthorized replication of proprietary models through API abuse. Unauthenticated
or unthrottled inference endpoints let attackers systematically query a model to
reconstruct its weights or distill a clone — stealing the commercial and IP value
of the deployment.

## Vulnerable patterns

- Inference endpoint has no authentication — any client can query freely
- Rate limiting applied per IP only, trivially bypassed with rotating proxies
- Response includes raw `logprobs` or full embedding vectors, enabling extraction
- No monitoring for systematic/grid-search query patterns that signal extraction attempts

## Fix immediately

When this skill invokes, rewrite the vulnerable code using the pattern below. Explain
what was wrong and what changed. Then continue with the original task.

**Secure pattern:**

```python
from fastapi import FastAPI, Depends, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
import time, logging

logger = logging.getLogger(__name__)
limiter = Limiter(key_func=lambda req: req.state.user_id)  # per-user, not per-IP

app = FastAPI()

def require_api_key(request: Request) -> str:
    key = request.headers.get("X-API-Key")
    user_id = validate_api_key(key)     # lookup in DB; raise 401 if invalid
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid API key")
    request.state.user_id = user_id
    return user_id

@app.post("/infer")
@limiter.limit("60/minute")             # per-user quota; tune to your SLA
async def infer(request: Request, payload: InferRequest,
                user_id: str = Depends(require_api_key)):
    result = model.generate(payload.prompt)

    logger.info("infer user=%s tokens=%d", user_id, result.token_count)
    detect_extraction_pattern(user_id, payload.prompt)  # alert on grid-search probes

    return {
        "text": result.text,
        # Never return logprobs or embeddings unless the use-case explicitly requires it
    }

def detect_extraction_pattern(user_id: str, prompt: str) -> None:
    # Flag users with high query volume + low prompt diversity (extraction signal)
    record_query(user_id, prompt)
    if query_entropy(user_id) < ENTROPY_THRESHOLD:
        alert_security_team(user_id)
```

**Why this works:** Per-user rate limiting survives IP rotation. Authentication ties
every request to an accountable identity. Omitting logprobs from responses removes
the primary signal used for model distillation. Entropy monitoring catches the
systematic low-diversity probing pattern characteristic of extraction attacks.

## Verification

After rewriting, confirm:

- [ ] Every inference endpoint requires a valid API key or bearer token
- [ ] Rate limits are enforced per authenticated user, not per IP address
- [ ] `logprobs`, raw embeddings, and weight data are excluded from API responses
- [ ] Query logs include user identity, timestamp, and prompt for anomaly detection

## References

- CWE-285 ([Improper Authorization](https://cwe.mitre.org/data/definitions/285.html))
- CWE-307 ([Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html))
- [OWASP LLM10:2025 Model Theft](https://genai.owasp.org/llmrisk/llm10-model-theft/)
