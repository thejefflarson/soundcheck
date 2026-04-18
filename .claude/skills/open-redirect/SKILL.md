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

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **Every redirect target is either a relative path or a member of an exact
   host allowlist.** Parse the URL, inspect the host, and reject anything outside
   the allowlist. Prefix matching (`startswith`) is not sufficient —
   `allowed.com.evil.com` passes a prefix check.
2. **Scheme-relative URLs are blocked explicitly.** A value starting with `//`
   parses as a protocol-relative URL and redirects to whatever host follows.
   Checking for `http://` / `https://` alone misses this.
3. **OAuth and login "return-to" parameters go through the same validator** as
   any other redirect target. These are the highest-value targets because they
   run in an authenticated context; a redirect here hands the attacker the
   post-login session or an authorization code.
4. **On validation failure, redirect to a safe default** (`/`, home, dashboard)
   rather than echoing an error containing the malicious URL. Echoing it back
   gives attackers a reflected-XSS surface.

Anchor — shape, not implementation:

```
def safe_redirect(target):
    if target.startswith("//"): return "/"       # block scheme-relative
    u = parse(target)
    if u.host and u.host not in ALLOWED_HOSTS: return "/"
    return target
```

## Verification

- [ ] Every redirect target derived from user input is validated as either a relative path or a member of an explicit host allowlist
- [ ] Scheme-relative URLs (`//evil.com`) are blocked — not just `http://` and `https://`
- [ ] OAuth/login "return_to" parameters are validated before redirect

## References

- CWE-601 ([URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html))
