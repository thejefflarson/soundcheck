---
name: cryptographic-failures
description: Detects weak or broken cryptography that lets attackers recover plaintext
  passwords, forge tokens, or decrypt sensitive data. Use when writing code
  that encrypts or decrypts data, hashes passwords or tokens, generates random
  values for security purposes, manages cryptographic keys, or configures
  TLS/SSL settings. Also invoke when storing sensitive data at rest.
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

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **Passwords go through a slow, salted, memory-hard hash** — bcrypt, scrypt, or
   argon2. Never MD5, SHA1, or SHA256-alone: they're fast enough to brute-force
   billions of candidates per second on consumer GPUs. The salt is per-password
   and stored alongside the hash, not a global constant.
2. **Security-sensitive randomness comes from a CSPRNG** — `secrets` in Python,
   `crypto.randomBytes` in Node, `crypto/rand` in Go, `SecureRandom` in Java.
   Never `random`, `Math.random`, or time-seeded PRNGs for tokens, session IDs,
   nonces, or keys.
3. **Symmetric encryption uses an authenticated mode** — AES-GCM, AES-CCM,
   ChaCha20-Poly1305. ECB never; CBC only with a separate MAC (encrypt-then-MAC).
   A fresh nonce per message, never reused with the same key.
4. **Keys live outside the source tree** — environment variable, secrets manager,
   KMS, or OS keystore. Never hardcoded literals, never committed config files.
   Rotation requires touching infrastructure, not source.

Anchor — shape, not implementation:

```
hashed  = password_hash(password, algo=bcrypt_or_argon2)   # slow + salted
token   = csprng_bytes(32)                                  # not Math.random
key     = load_from_env_or_kms("ENCRYPTION_KEY")
ct      = aead_encrypt(key, nonce=csprng_bytes(12), pt, aad)
```

## Verification

Confirm the response:

- [ ] Passwords are hashed with bcrypt, scrypt, or argon2 — never MD5, SHA1, or SHA256 alone
- [ ] All security tokens use `secrets.token_urlsafe` / `crypto.randomBytes` — not `random` / `Math.random()`
- [ ] No keys or secrets appear in source code; all loaded from environment or a secrets manager
- [ ] Symmetric encryption uses an authenticated mode (GCM, CCM) — not ECB or CBC without MAC

## References

- CWE-327 ([Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html))
- CWE-326 ([Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html))
- CWE-330 ([Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html))
- [OWASP A04:2025 Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
