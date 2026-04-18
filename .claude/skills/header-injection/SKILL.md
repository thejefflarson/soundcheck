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

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **Every header value derived from user input is stripped of CR/LF before it
   reaches the header-set call.** A single `\r\n` in a value ends the header block
   and starts a new header (or a new response body). The strip happens at or
   before the call site — relying on the framework to reject it is fragile
   across versions.
2. **Forwarded headers are sanitized too.** Values read from incoming requests
   (correlation IDs, user agents, custom headers) are attacker-controlled just
   like form inputs. Echoing them into outgoing responses or logs without
   stripping is the same vulnerability.
3. **Content-Disposition filenames are normalized** — CRLF stripped, quotes
   escaped, and for international characters use RFC 5987 `filename*=UTF-8''…`
   rather than raw UTF-8 in the header value.
4. **Redirect Location headers are validated too.** A CRLF in the target URL
   splits the response; see the `open-redirect` skill for target-host validation.

Anchor — shape, not implementation:

```
def safe_header(v): return v.replace("\r", "").replace("\n", "")
response.set_header("X-Custom",      safe_header(user_input))
response.set_header("Location",      safe_header(validated_url))
response.set_header("Content-Disposition", f'attachment; filename="{safe_header(name)}"')
```

## Verification

- [ ] Every HTTP response header value derived from user input has `\r` and `\n` characters stripped or rejected before being set
- [ ] Content-Disposition filenames from user input are sanitized for CRLF and special characters
- [ ] Forwarded headers (correlation IDs, request IDs) from incoming requests are sanitized before inclusion in outgoing responses

## References

- CWE-113 ([Improper Neutralization of CRLF Sequences in HTTP Headers](https://cwe.mitre.org/data/definitions/113.html))
- CWE-93 ([Improper Neutralization of CRLF Sequences](https://cwe.mitre.org/data/definitions/93.html))
