---
name: insecure-design
description: Use when designing authentication flows, implementing rate limiting, building
  business logic for financial or access-sensitive operations, or writing code that enforces
  security requirements at the application layer. Also invoke when designing multi-step
  workflows that change user state or permissions.
---

# Insecure Design Security Check (A06:2025)

## What this checks

Protects against flaws where security controls were never designed in — not bypassed, but simply absent. Missing rate limiting, skippable workflow steps, and unenforced re-authentication allow account takeover, fraud, and privilege escalation.

## Vulnerable patterns

- `def login(user, pw): ...` — no rate limiting or lockout after repeated failures
- `if step == "confirm_payment": process()` — client-supplied step can skip validation
- `if user_exists: "Invalid password" else: "User not found"` — reveals account existence
- Sensitive action (email change, fund transfer) with no re-authentication prompt

## Fix immediately

When this skill invokes, rewrite the vulnerable code using the pattern below. Explain what was wrong and what changed. Then continue with the original task.

**Secure pattern:**

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
    valid = user and hmac.compare_digest(hash_password(password), user.password_hash)
    if not valid:
        FAILED_ATTEMPTS[username] += 1
        return {"error": "Invalid credentials"}, 401
    FAILED_ATTEMPTS[username] = 0
    return {"token": create_session(user)}, 200

def require_reauth(user_id: str, password: str) -> bool:
    """Call before sensitive operations: email change, fund transfer, delete account."""
    user = db.get_user_by_id(user_id)
    return user and hmac.compare_digest(hash_password(password), user.password_hash)
```

**Why this works:** Rate limiting and lockout prevent brute force; uniform error messages prevent user enumeration; re-authentication gates privilege operations even inside an active session.

## Verification

After rewriting, confirm:

- [ ] Login and password-reset endpoints are rate-limited per IP and per username
- [ ] Account lockout triggers after N failed attempts with no bypass
- [ ] Error messages are identical for invalid username and invalid password
- [ ] Sensitive state changes (email, password, payment) require re-authentication
- [ ] Multi-step workflows validate step order server-side, not via client-supplied state

## References

- CWE-657 ([Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html))
- CWE-840 ([Business Logic Errors](https://cwe.mitre.org/data/definitions/840.html))
- [OWASP A06:2025 – Insecure Design](https://owasp.org/Top10/A06_2021-Insecure_Design/)
