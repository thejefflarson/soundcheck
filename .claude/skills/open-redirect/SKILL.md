---
name: open-redirect
description: Use when writing code that redirects users to a URL from request parameters,
  form input, or any caller-controlled source. Also invoke when building login flows
  with "return to" URLs or OAuth callback redirects.
---

# Open Redirect Security Check (CWE-601)

## What this checks

Protects against open redirect vulnerabilities where an attacker crafts a link that
redirects users from a trusted domain to a malicious site. Used in phishing campaigns
to make malicious links appear legitimate, and in OAuth flows to steal authorization
codes.

## Vulnerable patterns

- `redirect(request.args["next"])` — redirects to any URL the caller supplies
- `http.Redirect(w, r, r.URL.Query().Get("return"), 302)` — no validation
- `response.sendRedirect(req.getParameter("url"))` — Java unvalidated redirect
- `window.location = params.get("redirect")` — client-side open redirect

## Fix immediately

Flag the vulnerable code and explain the risk. Show the secure pattern below as a
suggested fix. Then continue with the original task.

**Secure pattern:**

```python
# Python/Flask — validate redirect is relative or in allowlist
from urllib.parse import urlparse

ALLOWED_HOSTS = {"myapp.com", "www.myapp.com"}

def safe_redirect(url: str) -> str:
    parsed = urlparse(url)
    # Allow only relative paths or known hosts
    if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:
        return "/"
    # Block scheme-relative URLs like //evil.com
    if url.startswith("//"):
        return "/"
    return url
```

```go
// Go — reject absolute URLs and foreign hosts
func safeRedirect(target string) string {
    u, err := url.Parse(target)
    if err != nil || u.IsAbs() || strings.HasPrefix(target, "//") {
        return "/"
    }
    return target
}
```

**Why this works:** Restricting redirects to relative paths or an explicit host
allowlist prevents attackers from directing users to external sites. Blocking
`//` prevents scheme-relative bypasses.

## Verification

- [ ] Every redirect target derived from user input is validated as either a relative path or a member of an explicit host allowlist
- [ ] Scheme-relative URLs (`//evil.com`) are blocked — not just `http://` and `https://`
- [ ] OAuth/login "return_to" parameters are validated before redirect

## References

- CWE-601 ([URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html))
