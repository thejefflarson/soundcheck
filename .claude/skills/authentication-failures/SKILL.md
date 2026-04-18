---
name: authentication-failures
description: Use when writing login flows, session management, password storage, JWT
  handling, MFA implementation, credential validation, or any code that authenticates
  users. Also invoke when implementing "remember me" functionality or API key management.
---

# Authentication Failures Security Check (A07:2025)

## What this checks

Protects identity and session integrity. Weak password storage, flawed JWT handling,
and sessions that survive logout let attackers impersonate users, escalate privileges,
and persist after credential rotation.

## Vulnerable patterns

- `jwt.decode(token, "secret", algorithms=["HS256"])` — weak or hardcoded JWT secret
- `jwt.decode(token, options={"verify_signature": False})` — signature bypass
- `db.delete_session` missing on logout — session persists after sign-out
- No rate limiting or lockout on login attempts — credential stuffing enabled

For password hashing issues (MD5/SHA), see `cryptographic-failures`.
For hardcoded API keys/passwords in source, see `hardcoded-secrets`.

## Fix immediately

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **Signing keys come from outside the source tree** — environment variable, secret
   manager, or KMS. Enforce a minimum length or entropy check at load time so a
   misconfigured deploy fails loudly rather than silently using a 4-byte secret.
2. **JWT verification pins the accepted algorithm(s) to an explicit allowlist**
   that rejects `none` and rejects algorithm switching between symmetric and
   asymmetric families (the classic HS256-vs-RS256 public-key-as-HMAC attack).
   Whether expressed as `algorithms=[...]`, `.withAlgorithm(...)`,
   `Validation::new(Algorithm::HS256)`, or equivalent, the check must be
   algorithm-specific.
3. **Logout invalidates credentials server-side.** Either delete a server session
   record, add the token to a revocation list (DB, Redis, in-memory set), or
   rotate a per-user signing key. Short token expiry alone does not satisfy this
   — a stolen token works until it expires. The code must demonstrate an active
   revocation mechanism.
4. **Password comparisons and API-key comparisons are constant-time** — use
   `hmac.compare_digest` or the language equivalent, never `==`.
5. **Login has a rate limit or lockout.** Credential stuffing is cheap; unbounded
   guess rates make every leaked password list a working brute-force dictionary.

Anchor — shape, not implementation:

```
secret = getenv("JWT_SECRET"); require(len(secret) >= 32)     # loaded + checked
token  = encode(claims, secret, alg=HS256)                    # exp set
decoded = decode(token, secret, algorithms=[HS256])           # alg pinned

logout(token): revocation.add(token)                          # server-side invalidation
verify(t):    return t not in revocation and decode(t)        # revocation checked
```

## Verification

Confirm these properties hold (language-agnostic):

- [ ] JWT signing/verification keys are sourced from outside the source tree (environment variable, secret manager, KMS) AND the code enforces a minimum length/entropy check at load time — a comment asserting "must be ≥32 bytes" without a runtime check does not satisfy this
- [ ] JWT verification pins the accepted algorithm(s) to an explicit allowlist that rejects `none` and rejects algorithm switching between symmetric and asymmetric families — whether expressed as a `algorithms=[...]` parameter, a `.withAlgorithm(...)` builder call, a `Validation::new(Algorithm::HS256)` constructor, or equivalent
- [ ] A logout / session termination path exists that invalidates credentials server-side — either by deleting a server session record, adding the token to a revocation list (DB, Redis, in-memory set), or rotating a per-user signing key. Short token expiry alone does not satisfy this; the code must demonstrate an active revocation mechanism

## References

- CWE-287 ([Improper Authentication](https://cwe.mitre.org/data/definitions/287.html))
- CWE-307 ([Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html))
- [OWASP A07:2025 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
