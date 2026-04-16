---
name: oauth-implementation
description: Use when writing OAuth2 or OpenID Connect flows, JWT validation logic,
  token endpoint handling, or redirect URI processing. Also invoke when implementing
  any code that parses or verifies JWTs.
---

# OAuth/OIDC Implementation Security (OWASP A07:2025)

## What this checks

Prevents authentication bypasses from weak JWT validation, open redirects from loose
`redirect_uri` matching, and CSRF from missing `state` parameters. These flaws allow
account takeover and session hijacking.

## Vulnerable patterns

- `jwt.decode(token, key, algorithms=["none"])` — algorithm confusion bypasses signature
- `redirect_uri.startswith(allowed)` — prefix match allows `evil-example.com` bypass
- `jwt.decode(token, key)` — no algorithm restriction or audience check
- Storing tokens in `localStorage` — accessible to any XSS payload
- No `state` parameter generated or validated — CSRF against OAuth flow

## Fix immediately

When this skill invokes, rewrite the vulnerable code using the pattern below. Explain
what was wrong and what changed. Then continue with the original task.

**Secure pattern:**

```python
import secrets
import jwt  # PyJWT

ALLOWED_REDIRECT_URIS = {"https://app.example.com/callback"}
ALGORITHM = "RS256"

# OAuth initiation — generate and store state
def start_oauth(session: dict) -> str:
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    return f"https://idp.example.com/auth?state={state}&..."

# Redirect URI validation — exact match only
def validate_redirect(uri: str) -> str:
    if uri not in ALLOWED_REDIRECT_URIS:
        raise ValueError("Invalid redirect_uri")
    return uri

# JWT validation — explicit algorithm, full claim check
def validate_token(token: str, public_key: str, audience: str) -> dict:
    return jwt.decode(
        token,
        public_key,
        algorithms=[ALGORITHM],           # explicit allowlist, never "none"
        audience=audience,                # reject wrong-audience tokens
        options={"require": ["exp", "iat", "sub"]},
    )
```

**Why this works:** Algorithm allowlist blocks `alg:none` attacks. Exact URI matching
prevents open redirect. Full claim validation catches replayed or misrouted tokens.
State parameter ties the callback to the initiating session.

## Verification

After rewriting, confirm:

- [ ] `algorithms=` is an explicit allowlist — never includes `"none"`
- [ ] `redirect_uri` checked with exact match against an allowlist set
- [ ] `audience` validated in every JWT decode call
- [ ] `state` parameter generated and validated against stored session value

## References

- CWE-287 ([Improper Authentication](https://cwe.mitre.org/data/definitions/287.html))
- CWE-601 ([Open Redirect](https://cwe.mitre.org/data/definitions/601.html))
- CWE-346 ([Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html))
- [OWASP A07:2025 Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
