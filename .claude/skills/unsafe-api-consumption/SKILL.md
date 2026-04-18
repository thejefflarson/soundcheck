---
name: unsafe-api-consumption
description: Use when writing code that calls third-party APIs, parses responses from
  external services, or integrates with webhooks and callbacks from external systems.
  Also invoke when deserializing or acting on data received from partner or vendor APIs
  without validation.
---

# Unsafe API Consumption Check (API10:2023)

## What this checks

Protects against blindly trusting data from third-party APIs. External API responses
can be tampered with (via MITM, compromised provider, or supply-chain attack), contain
unexpected types or malicious payloads, or change without notice. Treating external
data as trusted leads to injection, deserialization attacks, and business logic bypass.

## Vulnerable patterns

- `data = requests.get(api_url).json(); db.execute(f"INSERT ... {data['name']}")` — external data into SQL
- `html := resp.Body; template.HTML(html)` — rendering third-party HTML without sanitization
- `Object.assign(user, externalApiResponse)` — merging unvalidated external fields into internal model
- `redirect(api_response["redirect_url"])` — following redirect from untrusted API response (open redirect / SSRF)
- `exec(api_response["script"])` — executing code from external API

## Fix immediately

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **Every response is validated against an explicit schema** — typed struct, Pydantic
   model, JSON Schema, protobuf message, or equivalent — before any field reaches
   business logic. Optional fields get defaults; unexpected fields are rejected or
   ignored, not silently propagated.
2. **External data never reaches injection sinks via string interpolation.** SQL
   goes through parameterized queries; HTML goes through an auto-escaping template
   engine; shell goes through argv arrays. Validation does not exempt the sink.
3. **Response size is bounded and the request has a timeout.** A partner API can
   stream gigabytes or hang forever; both eat resources and can DoS the caller.
4. **Redirects are not followed blindly.** Either disable redirects, or re-validate
   each hop against the same allowlist used for the initial URL. Partner-controlled
   3xx responses can redirect to SSRF targets or attacker-controlled hosts.

Anchor — shape, not implementation:

```
resp = http_get(url, timeout=10, follow_redirects=False)
require(len(resp.body) < MAX_BYTES)
data = validate(parse(resp.body), schema=ExpectedShape)   # reject unknowns
use(data)                                                  # only validated fields reach sinks
```

## Verification

- [ ] Every response from an external API is validated against a schema (typed struct, Pydantic model, JSON Schema, or equivalent) before any field is used in queries, rendering, or business logic
- [ ] External API data never reaches SQL, shell, template, or code-execution sinks via string interpolation — only through parameterized/auto-escaping interfaces
- [ ] HTTP responses from external APIs are size-limited to prevent resource exhaustion
- [ ] Redirects from external API responses are either disabled or re-validated at each hop against the same allowlist used for the initial URL

## References

- CWE-20 ([Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html))
- CWE-502 ([Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html))
- [OWASP API10:2023 Unsafe Consumption of APIs](https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/)
