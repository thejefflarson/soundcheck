---
name: crypto-library-misuse
description: Detects library-internal cryptographic correctness bugs that pattern matchers and crypto-failures skills miss — AEAD nonce reuse, ECDSA k-value reuse, length-extension on bare hashes, padding-oracle exception distinguishability, and branching on secret material. Use when writing code that calls a crypto primitive directly (AEAD encrypt/decrypt, ECDSA/DSA sign, raw hash, RSA decrypt). Distinct from cryptographic-failures, which covers application-layer choices like MD5 for passwords; this skill is about how primitives are wired up.
---

# Crypto Library Misuse (CWE-323, CWE-330, CWE-208)

## What this checks

Cryptographic primitives are correct only when their preconditions
are met. Not "weak algorithm picked" — that's `cryptographic-failures`.
These are "right primitive, wrong wiring": nonce reused, per-signature
random reused, comparison branches on secret bits, exception type
leaks which decryption failure happened. Each pattern below has
produced a real CVE (Sony PS3 ECDSA k-reuse, Marvin Attack RSA timing).

## Vulnerable patterns

- **AEAD nonce reuse**: `aes_gcm.encrypt(nonce, pt, aad)` where
  `nonce` is `\x00 * 12` or a counter that wraps. With a single
  reused nonce, an attacker XORs two ciphertexts and recovers
  both plaintexts.
- **ECDSA/DSA k reuse or weak randomness**: signing with a
  predictable or repeated per-signature random value, or using
  the system RNG without checking it's been seeded. Two signatures
  with the same k recover the private key by linear algebra.
- **Length-extension on bare hashes**: `auth = sha256(secret || msg);`
  used as a MAC. SHA-2 length-extension means an attacker who
  knows the auth and `len(secret)` can compute `sha256(secret || msg || padding || extra)`.
- **Padding oracle via exception distinguishability**: catching
  one exception type for "ciphertext too short" and a different
  type for "padding invalid". The Bleichenbacher and Manger
  attacks need exactly that one bit per query.
- **Branching on secret material**: `if (key_bit[i]) ... else ...`
  produces a measurable timing difference. Includes early-exit
  byte comparison on MACs (`memcmp` instead of `CRYPTO_memcmp`).
- **Static IV for CBC**: encrypting two plaintexts with the same
  IV reveals their common prefix.
- **ECB used for structured data**: same plaintext block → same
  ciphertext block, leaks structure.

## Fix immediately

When this skill invokes, rewrite the call site to ensure
preconditions are met.

**Secure AEAD with fresh nonce:**

```python
# Each encrypt gets a fresh random 96-bit nonce; never reused.
nonce = secrets.token_bytes(12)
ct = AESGCM(key).encrypt(nonce, pt, aad)
# Caller MUST store/transmit nonce alongside ct.
```

**Secure ECDSA signing:**

```python
# Library does RFC 6979 deterministic k internally; never roll your own.
sig = key.sign(msg, ec.ECDSA(hashes.SHA256()))
```

**Secure MAC instead of length-extendable hash:**

```python
import hmac, hashlib
auth = hmac.new(secret, msg, hashlib.sha256).digest()
# HMAC is not length-extension vulnerable; SHA-256 alone is.
```

**Constant-time comparison:**

```python
import hmac
ok = hmac.compare_digest(expected, received)
```

**Single exception type for all decrypt failures:**

```python
try:
    pt = rsa_decrypt(ct)
except (InvalidPadding, InvalidLength, DecryptionFailed) as e:
    raise DecryptionError("decryption failed") from None  # collapse
```

**Why this works:** AEAD with a fresh random nonce avoids the
two-ciphertext-XOR attack. RFC 6979 derives k deterministically
from key+message so reuse is impossible. HMAC's two-pass construction
defeats length-extension. `compare_digest` and `CRYPTO_memcmp` take
constant time regardless of where the mismatch falls. Collapsing
exception types removes the oracle bit.

## Verification

After rewriting, confirm:

- [ ] Every AEAD encrypt site uses a freshly-generated nonce
      from a CSPRNG, OR an explicitly-managed monotonic counter
      with an overflow check
- [ ] No call to `sign()` passes a caller-supplied k unless the
      function name explicitly says "deterministic" (RFC 6979)
- [ ] No MAC is implemented as `hash(secret || msg)`; HMAC or a
      MAC primitive (Poly1305, KMAC) is used
- [ ] All MAC / signature / hash comparisons use a constant-time
      primitive (`hmac.compare_digest`, `CRYPTO_memcmp`,
      `subtle.ConstantTimeCompare`), never `==` or `memcmp`
- [ ] All decryption failures raise the same exception type at
      the boundary
- [ ] No branch in the crypto routine depends on a secret bit

## References

- CWE-323 ([Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html))
- CWE-330 ([Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html))
- CWE-208 ([Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html))
- CWE-326 ([Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html))
