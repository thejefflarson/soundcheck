---
name: ssrf
description: Use when writing code that makes HTTP requests to URLs constructed from
  user input, fetches resources from caller-specified addresses, or proxies requests
  on behalf of users. Also invoke when implementing webhook receivers or URL preview
  features.
---

# SSRF Security Check (A10:2025 / API7:2023)

## What this checks

Protects against Server-Side Request Forgery where an attacker tricks the server into
making requests to internal services, cloud metadata endpoints, or arbitrary external
hosts. Exploitation leads to internal network scanning, credential theft from cloud
metadata APIs (169.254.169.254), and access to services behind firewalls.

## Vulnerable patterns

- `requests.get(user_url)` — fetches any URL the caller supplies, including `http://169.254.169.254/`
- `http.Get(fmt.Sprintf("http://%s/api", userHost))` — host from user input reaches outbound request
- `fetch(req.body.webhookUrl)` — webhook callback to attacker-controlled or internal address
- `new URL(input).openStream()` — Java URL fetch with no host validation, follows redirects to internal IPs
- `HttpClient.send(HttpRequest.newBuilder().uri(URI.create(userInput)).build())` — unchecked URI

## Fix immediately

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties. **Proxy, webhook, and URL-preview features are the highest-risk
shapes** — the scheme/host/IP/redirect checks must actually run at the call site
before the outbound request; a comment saying "URL should be validated" or
principles repeated in prose do not satisfy anything if the code just calls
`http.Get(userURL)`.

1. **Scheme is restricted to `https` (and maybe `http` for trusted internal use).**
   Reject `file:`, `gopher:`, `ftp:`, `dict:`, and other schemes that SSRF toolkits
   exploit.
2. **Host is checked against an allowlist, and the resolved IP is checked against a
   blocklist covering private, loopback, and link-local ranges** — IPv4
   `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`
   and IPv6 `::1/128`, `fc00::/7`, `fe80::/10`. Resolve-then-check catches DNS
   rebinding; an allowlisted hostname can still resolve to `169.254.169.254`.
   Language-idiomatic checks that cover the same ranges (Java
   `isLinkLocalAddress() + isSiteLocalAddress()`; Go `IsLinkLocalUnicast() +
   IsPrivate()`) are equivalent to the explicit CIDR form.
3. **Redirects are disabled, or each redirect target is re-validated against the
   same allowlist.** A lone allowlisted host can still 302 you to an internal IP.
4. **The check actually runs.** A blocklist declared and never evaluated does not
   satisfy any of the above — reviewers should see the comparison.

Anchor — shape, not implementation:

```
u = parse(url)
require(u.scheme in ALLOWED_SCHEMES)
require(u.host in ALLOWED_HOSTS)
require(resolve(u.host) not in BLOCKED_NETS)   # defeats DNS rebinding
fetch(u, follow_redirects=False)               # or re-validate each hop
```

## Verification

- [ ] Every outbound HTTP request using a caller-supplied URL validates the scheme, host, and resolved IP against an allowlist or blocklist before the request is sent
- [ ] Cloud metadata and link-local addresses are blocked — either via explicit CIDR entries covering `169.254.0.0/16`, `fe80::/10`, and `fc00::/7`, or via language-idiomatic checks that cover the same ranges. Declaring a list without evaluating it does not satisfy this
- [ ] HTTP redirects are disabled, or each redirect target is re-validated against the same allowlist
- [ ] DNS resolution results are checked for private/loopback/link-local IPs before connecting

## References

- CWE-918 ([Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html))
- [OWASP A10:2025 Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
- [OWASP API7:2023 Server Side Request Forgery](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/)
