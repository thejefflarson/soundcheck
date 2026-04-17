---
name: header-injection
description: Use when writing code that sets HTTP response headers using values from
  user input, request parameters, or external data. Also invoke when constructing
  email headers, Content-Disposition filenames, or Location headers from caller-controlled
  strings.
---

# HTTP Header Injection Security Check (CWE-113)

## What this checks

Protects against HTTP response header injection where user input containing `\r\n`
(CRLF) characters is included in response headers, allowing attackers to inject
arbitrary headers or split the HTTP response. Exploitation leads to cache poisoning,
session fixation, XSS via injected headers, and response splitting.

## Vulnerable patterns

- `response.headers["X-Custom"] = user_input` — CRLF in input injects new headers
- `w.Header().Set("Content-Disposition", "attachment; filename=" + filename)` — newlines in filename
- `ctx.set("Location", redirectUrl)` — CRLF splits response
- `resp.setHeader("X-Request-Id", req.getHeader("X-Correlation-Id"))` — forwarding unsanitized header

## Fix immediately

Flag the vulnerable code and explain the risk. Show the secure pattern below as a
suggested fix. Then continue with the original task.

**Secure pattern:**

```python
# Python — strip CRLF from any value used in headers
import re

def safe_header_value(value: str) -> str:
    return re.sub(r"[\r\n]", "", value)

response.headers["X-Custom"] = safe_header_value(user_input)
```

```go
// Go — net/http rejects \r\n in header values since Go 1.21
// For older versions or extra safety:
func safeHeaderValue(v string) string {
    return strings.NewReplacer("\r", "", "\n", "").Replace(v)
}
w.Header().Set("X-Custom", safeHeaderValue(userInput))
```

```javascript
// Node.js — Express rejects headers with \r\n since v4
// For explicit safety:
const safeValue = userInput.replace(/[\r\n]/g, "");
res.set("X-Custom", safeValue);
```

**Why this works:** Stripping carriage return and newline characters from header values
eliminates the injection vector. Modern frameworks increasingly reject these by default,
but explicit sanitization prevents regressions and covers edge cases.

## Verification

- [ ] Every HTTP response header value derived from user input has `\r` and `\n` characters stripped or rejected before being set
- [ ] Content-Disposition filenames from user input are sanitized for CRLF and special characters
- [ ] Forwarded headers (correlation IDs, request IDs) from incoming requests are sanitized before inclusion in outgoing responses

## References

- CWE-113 ([Improper Neutralization of CRLF Sequences in HTTP Headers](https://cwe.mitre.org/data/definitions/113.html))
- CWE-93 ([Improper Neutralization of CRLF Sequences](https://cwe.mitre.org/data/definitions/93.html))
