---
name: insecure-design
description: Use when designing authentication flows, implementing rate limiting, building
  business logic for financial or access-sensitive operations, or writing code that enforces
  security requirements at the application layer.
---

# Insecure Design Security Check (A06:2025)

## What this checks

Catches security controls that were never designed in. Missing rate limiting, skippable workflow steps, and unenforced re-authentication enable account takeover, fraud, and privilege escalation.

## Vulnerable patterns

- `def login(user, pw): ...` — no rate limiting or lockout
- `if step == "confirm_payment": process()` — client-supplied step skips validation
- `if user_exists: "Invalid password" else: "User not found"` — reveals account existence
- Sensitive action (email change, fund transfer) with no re-authentication

## Fix immediately

Rewrite the vulnerable code using the pattern below. Explain the change, then continue with the original task.

```python
import time
import hmac
from collections import defaultdict

# Token bucket rate limiter
_buckets: dict[str, tuple[float, int]] = defaultdict(lambda: (time.monotonic(), 10))

def check_rate_limit(key: str, capacity: int = 10, refill_rate: float = 1.0) -> bool:
    last, tokens = _buckets[key]
    now = time.monotonic()
    tokens = min(capacity, tokens + (now - last) * refill_rate)
    _buckets[key] = (now, tokens)
    if tokens < 1:
        return False
    _buckets[key] = (now, tokens - 1)
    return True

FAILED_ATTEMPTS: dict[str, int] = defaultdict(int)
LOCKOUT_THRESHOLD = 5

def login(username: str, password: str, ip: str) -> dict:
    if not check_rate_limit(f"login:{ip}"):
        return {"error": "Too many requests"}, 429
    if FAILED_ATTEMPTS[username] >= LOCKOUT_THRESHOLD:
        return {"error": "Account locked. Contact support."}, 403
    user = db.get_user(username)
    pw_hash = hash_password(password)
    stored = user.password_hash if user else pw_hash  # dummy hash equalizes timing
    valid = hmac.compare_digest(pw_hash, stored) and user is not None
    if not valid:
        FAILED_ATTEMPTS[username] += 1
        return {"error": "Invalid credentials"}, 401
    FAILED_ATTEMPTS[username] = 0
    return {"token": create_session(user)}, 200

def require_reauth(user_id: str, password: str) -> bool:
    """Gate sensitive operations: email change, fund transfer, account deletion."""
    if not check_rate_limit(f"reauth:{user_id}"):
        return False
    user = db.get_user_by_id(user_id)
    pw_hash = hash_password(password)
    stored = user.password_hash if user else pw_hash
    return hmac.compare_digest(pw_hash, stored) and user is not None
```

**Why this works:** Rate limiting prevents brute force; uniform errors prevent user enumeration; re-auth gates privilege operations inside active sessions.

**Common pitfalls to avoid:**

- **Timing:** Always compute the hash even when the user is missing -- compare against a dummy hash to equalize timing. Never short-circuit via `user and hmac.compare_digest(...)`.
- **Step state:** Read the current step from server-side state (session/DB), never from a client-supplied parameter like `step=confirm`.
- **Rate limits:** Apply to EVERY credential-accepting endpoint, not just login -- include reset, purchase, re-auth, and any endpoint accepting a password or OTP.

## Verification

After rewriting, confirm the following *properties* hold for every endpoint present in the code under review (language-agnostic; criteria apply only to patterns actually present):

- [ ] Every credential-accepting endpoint present (login, password reset, MFA verify, token exchange) is gated by at least one rate-limiting or lockout mechanism keyed on a caller-controlled identifier (IP, username, email, or account id) — unlimited retries are not permitted
- [ ] Authentication failure responses do not distinguish "user not found" from "wrong password" via message text, status code, or response timing
- [ ] Any sensitive state-change operation present in the code (password change, email change, fund transfer, account deletion, permission grant) performs an authorization check stronger than "session exists" — e.g., re-prompts for the current password, verifies a step-up token, or requires an MFA challenge
- [ ] Multi-step workflows present in the code determine the current step from server-side state (session, database, signed token), not from a client-supplied step name, token, or boolean
- [ ] No security-relevant decision (lockout status, step progression, authorization level) is read from request parameters, cookies, or headers that the client can freely modify

## References

- CWE-657 ([Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html))
- CWE-840 ([Business Logic Errors](https://cwe.mitre.org/data/definitions/840.html))
- [OWASP A06:2025 – Insecure Design](https://owasp.org/Top10/A06_2021-Insecure_Design/)
