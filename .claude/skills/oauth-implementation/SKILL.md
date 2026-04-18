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

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **JWT verification pins algorithms to an explicit allowlist** that never
   includes `none` and rejects switching between symmetric and asymmetric
   families (the classic HS256/RS256 public-key-as-HMAC attack). For broader JWT
   handling guidance, see the `authentication-failures` skill.
2. **Redirect URIs match exactly against an allowlist set.** Prefix matching
   (`startswith`), substring matching, and regex matching all have known bypass
   classes — `evil-example.com`, percent-encoded tricks, userinfo smuggling. The
   only safe comparison is exact string equality against a set of registered
   URIs.
3. **Every JWT decode validates `aud` (audience) and required claims.** A token
   minted for a different service of the same issuer will validate the
   signature; only the audience check catches the confused-deputy case. Require
   `exp`, `iat`, `sub` at minimum.
4. **State parameter ties the callback to the initiating session.** Generate a
   CSPRNG `state`, store it in the session before redirect, compare it on the
   callback. Without this the OAuth flow is CSRF-forgeable.
5. **Tokens live in a Secure, HttpOnly, SameSite cookie or in memory — not
   `localStorage`.** Web storage is readable by any same-origin script, so one
   XSS compromise exfiltrates every token.

Anchor — shape, not implementation:

```
# callback
require(request.state == session.pop("oauth_state"))
require(request.redirect_uri in ALLOWED_REDIRECT_URIS)       # exact match
claims = jwt_decode(token, pubkey,
                    algorithms=["RS256"], audience=MY_AUD,
                    require=["exp","iat","sub"])
```

## Verification

Confirm the response:

- [ ] `algorithms=` is an explicit allowlist — never includes `"none"`
- [ ] `redirect_uri` checked with exact match against an allowlist set
- [ ] `audience` validated in every JWT decode call
- [ ] `state` parameter generated and validated against stored session value

## References

- CWE-287 ([Improper Authentication](https://cwe.mitre.org/data/definitions/287.html))
- CWE-601 ([Open Redirect](https://cwe.mitre.org/data/definitions/601.html))
- CWE-346 ([Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html))
- [OWASP A07:2025 Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
