---
name: cryptographic-failures
description: Use when writing code that encrypts or decrypts data, hashes passwords
  or tokens, generates random values for security purposes, manages cryptographic
  keys, or configures TLS/SSL settings. Also invoke when storing sensitive data at rest.
---

# Cryptographic Failures Security Check (A04:2025)

## What this checks

Protects against weak or broken cryptography that allows attackers to recover
plaintext passwords, forge tokens, or decrypt sensitive data. Failures here
directly enable credential stuffing, account takeover, and data breach.

## Vulnerable patterns

- `hashlib.md5(password.encode()).hexdigest()` — MD5 is broken; no salt, trivially reversed with rainbow tables
- `token = str(random.random())` — `Math.random()` / `random` is not cryptographically secure
- `SECRET_KEY = "hardcoded-secret"` — key committed to source control
- `AES.new(key, AES.MODE_ECB)` — ECB mode leaks patterns; identical plaintext blocks produce identical ciphertext

## Fix immediately

When this skill invokes, rewrite the vulnerable code using the pattern below. Explain
what was wrong and what changed. Then continue with the original task.

**Secure pattern:**

```python
# Password hashing — use bcrypt or argon2
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
# Verify:
bcrypt.checkpw(password.encode(), hashed)

# Secure random token — Python
import secrets
token = secrets.token_urlsafe(32)   # 256 bits of CSPRNG output

# Secure random token — Node.js
const crypto = require("crypto");
const token = crypto.randomBytes(32).toString("hex");

# Symmetric encryption — AES-256-GCM (authenticated)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = AESGCM.generate_key(bit_length=256)   # store in secrets manager, not source
aesgcm = AESGCM(key)
nonce = secrets.token_bytes(12)             # unique per message
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

# Key from environment
import os
SECRET_KEY = os.environ["SECRET_KEY"]   # never hardcode
```

**Why this works:** bcrypt/argon2 are slow by design and include a salt, defeating
rainbow tables. `secrets` / `crypto.randomBytes` use the OS CSPRNG. AES-GCM
provides both confidentiality and integrity; ECB provides neither.

## Verification

After rewriting, confirm:

- [ ] Passwords are hashed with bcrypt, scrypt, or argon2 — never MD5, SHA1, or SHA256 alone
- [ ] All security tokens use `secrets.token_urlsafe` / `crypto.randomBytes` — not `random` / `Math.random()`
- [ ] No keys or secrets appear in source code; all loaded from environment or a secrets manager
- [ ] Symmetric encryption uses an authenticated mode (GCM, CCM) — not ECB or CBC without MAC

## References

- CWE-327 ([Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html))
- CWE-326 ([Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html))
- CWE-330 ([Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html))
- [OWASP A04:2025 Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
