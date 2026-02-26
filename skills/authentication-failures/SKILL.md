---
name: authentication-failures
description: Use when writing login flows, session management, password storage, JWT
  handling, MFA implementation, credential validation, or any code that authenticates
  users. Also invoke when implementing "remember me" functionality or API key management.
---

# Authentication Failures Security Check (A07:2025)

## What this checks

Protects identity and session integrity. Weak password storage, flawed JWT handling, and sessions that survive logout let attackers impersonate users, escalate privileges, and persist after credential rotation.

## Vulnerable patterns

- `hashlib.md5(password.encode()).hexdigest()` — fast hash; trivially cracked offline
- `jwt.decode(token, "secret", algorithms=["HS256"])` — weak or hardcoded JWT secret
- `jwt.decode(token, options={"verify_signature": False})` — signature bypass
- `db.delete_session` missing on logout — session persists after sign-out
- `API_KEY = "sk-prod-abc123"` — hardcoded credential in source

## Fix immediately

When this skill invokes, rewrite the vulnerable code using the pattern below. Explain what was wrong and what changed. Then continue with the original task.

**Secure pattern:**

```python
import os
import hmac
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone

# --- Password storage ---
def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)

# --- JWT: secret from env, short expiry, no alg:none ---
JWT_SECRET = os.environ["JWT_SECRET"]          # min 32 random bytes
JWT_ALGORITHM = "HS256"

def create_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token: str) -> dict:
    # algorithms list prevents alg-switching attacks
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

# --- Session invalidation on logout ---
REVOKED: set[str] = set()   # replace with Redis/DB in production

def logout(token: str) -> None:
    REVOKED.add(token)

def is_valid_session(token: str) -> bool:
    if token in REVOKED:
        return False
    try:
        verify_token(token)
        return True
    except jwt.PyJWTError:
        return False

# --- Token comparison (timing-safe) ---
def verify_api_key(provided: str, stored: str) -> bool:
    return hmac.compare_digest(provided.encode(), stored.encode())
```

**Why this works:** bcrypt with rounds=12 makes offline cracking infeasible; env-sourced secrets keep credentials out of source; explicit algorithm list blocks alg:none; revocation ensures logout is real.

## Verification

After rewriting, confirm:

- [ ] Passwords hashed with bcrypt, scrypt, or Argon2 — never MD5, SHA-1, or SHA-256 alone
- [ ] JWT secret loaded from environment variable, ≥32 bytes of entropy
- [ ] `algorithms` parameter is an explicit allowlist in every `jwt.decode` call
- [ ] Logout invalidates the server-side session or adds token to a revocation list
- [ ] No credentials appear in source code, config files, or logs

## References

- CWE-287 ([Improper Authentication](https://cwe.mitre.org/data/definitions/287.html))
- CWE-307 ([Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html))
- CWE-798 ([Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html))
- [OWASP A07:2025 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
