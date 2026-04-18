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

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **Every inference endpoint requires authentication** — API key, bearer token,
   or mTLS. Unauthenticated endpoints are free training data for anyone who
   wants to clone the model.
2. **Rate limits are keyed on the authenticated principal, not the IP.** IP-only
   throttles are defeated by rotating proxies and residential IP pools; a
   per-user/per-key quota follows the attacker even as IPs churn.
3. **Extraction-signal fields are stripped from responses.** `logprobs`, full
   embedding vectors, and per-token probabilities are the primary signals
   distillation attacks use to reconstruct a model. If a caller doesn't strictly
   need them, don't return them.
4. **Query patterns are monitored for extraction signatures** — high-volume,
   low-entropy, systematic grid-search probes. Alerts fire on anomalies; the
   handler records user identity, timestamp, and prompt for after-the-fact
   investigation.

Anchor — shape, not implementation:

```
require(valid_api_key(request))                    # authenticated
require(rate_limit.allow(request.user_id))         # per-user, not per-IP
result = model.generate(prompt)
log_query(user_id, prompt, result.tokens)
detect_extraction_pattern(user_id, prompt)         # entropy-based alert
return { text: result.text }                       # no logprobs, no embeddings
```

## Verification

- [ ] Every inference endpoint requires a valid API key or bearer token
- [ ] Rate limits are enforced per authenticated user, not per IP address
- [ ] `logprobs`, raw embeddings, and weight data are excluded from API responses
- [ ] Query logs include user identity, timestamp, and prompt for anomaly detection

## References

- CWE-285 ([Improper Authorization](https://cwe.mitre.org/data/definitions/285.html))
- CWE-307 ([Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html))
- [OWASP LLM10:2025 Model Theft](https://genai.owasp.org/llmrisk/llm10-model-theft/)
