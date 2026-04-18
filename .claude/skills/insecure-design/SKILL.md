---
name: insecure-design
description: Use when designing authentication flows, implementing rate limiting, building
  business logic for financial or access-sensitive operations, or writing code that enforces
  security requirements at the application layer.
---

# Insecure Design Security Check (A06:2025)

## What this checks

Catches security controls that were never designed in. Missing rate limiting,
skippable workflow steps, and unenforced re-authentication enable account takeover,
fraud, and privilege escalation.

## Vulnerable patterns

- `def login(user, pw): ...` — no rate limiting or lockout
- `if step == "confirm_payment": process()` — client-supplied step skips validation
- `if user_exists: "Invalid password" else: "User not found"` — reveals account existence
- Sensitive action (email change, fund transfer) with no re-authentication

## Fix immediately

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **Every credential-accepting endpoint has a rate limit or lockout keyed on a
   caller-controlled identifier** (IP, username, email, or account id). Apply to
   *every* such endpoint — login, password reset, MFA verify, token exchange,
   re-auth — not just login. Unlimited retries are never acceptable.
2. **Authentication failure responses do not distinguish "user not found" from
   "wrong password"** — same message, same status code, same timing. Always
   compute the hash even when the user is missing (compare against a dummy hash
   to equalize latency); short-circuit branches leak account existence.
3. **Sensitive state changes (password change, email change, fund transfer, account
   deletion, permission grant) require a check stronger than "session exists"** —
   re-prompt for the current password, verify a step-up token, or require MFA.
4. **Multi-step workflows read the current step from server-side state** —
   session, database, or a signed token — never from a client-supplied parameter
   like `?step=confirm`. The server owns the progression.
5. **No security-relevant decision (lockout status, step progression,
   authorization level) is read from request parameters, cookies, or headers that
   the client can freely modify.**

Anchor — shape, not implementation:

```
endpoint login(user, pw, ip):
    require(rate_limiter.allow("login:" + ip))           # every cred endpoint
    require(not is_locked(user))
    valid = constant_time_compare(hash(pw), stored_or_dummy)
    if not valid: record_failure(user); respond_uniform_error()
    ...

endpoint change_email(new_email, current_pw):
    require(reauth(session.user, current_pw))            # step up, not just session
    ...
```

## Verification

Confirm these properties hold for every endpoint present (language-agnostic;
criteria apply only to patterns actually present):

- [ ] Every credential-accepting endpoint present (login, password reset, MFA verify, token exchange) is gated by at least one rate-limiting or lockout mechanism keyed on a caller-controlled identifier (IP, username, email, or account id) — unlimited retries are not permitted
- [ ] Authentication failure responses do not distinguish "user not found" from "wrong password" via message text, status code, or response timing
- [ ] Any sensitive state-change operation present in the code (password change, email change, fund transfer, account deletion, permission grant) performs an authorization check stronger than "session exists" — e.g., re-prompts for the current password, verifies a step-up token, or requires an MFA challenge
- [ ] Multi-step workflows present in the code determine the current step from server-side state (session, database, signed token), not from a client-supplied step name, token, or boolean
- [ ] No security-relevant decision (lockout status, step progression, authorization level) is read from request parameters, cookies, or headers that the client can freely modify

## References

- CWE-657 ([Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html))
- CWE-840 ([Business Logic Errors](https://cwe.mitre.org/data/definitions/840.html))
- [OWASP A06:2025 – Insecure Design](https://owasp.org/Top10/A06_2021-Insecure_Design/)
