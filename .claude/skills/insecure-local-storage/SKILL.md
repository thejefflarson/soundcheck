---
name: insecure-local-storage
description: Use when writing code that stores sensitive data (credentials, tokens, PII)
  to local files, platform preference stores (NSUserDefaults, SharedPreferences,
  UserDefaults), SQLite databases, or localStorage without encryption at rest.
---

# Insecure Local Data Storage (A02:2025)

## What this checks

Detects sensitive data written to unprotected local storage. Cleartext storage lets any
process with file-system access, or a device backup restore, harvest credentials and
tokens without authentication.

## Vulnerable patterns

- `open("config.json", "w"); json.dump({"token": token}, f)` — credentials in plaintext file
- `SharedPreferences.edit().putString("api_key", key)` — Android prefs without encryption
- `NSUserDefaults.standard.set(password, forKey: "password")` — iOS defaults without Keychain
- `localStorage.setItem("auth_token", token)` — web storage without at-rest encryption
- `tempfile.NamedTemporaryFile(); f.write(secret)` — secrets in world-readable temp files

## Fix immediately

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **Sensitive values go to platform-managed secure storage, not a plain file or
   pref store.** OS keychain (Python `keyring`, iOS Keychain, macOS Keychain),
   Android `EncryptedSharedPreferences`, Windows DPAPI / Credential Manager.
   These encrypt at rest and scope access to the owning process.
2. **Web clients do not store long-lived credentials in `localStorage` or
   `sessionStorage`.** These are readable by any script on the origin — one XSS
   and the token is gone. Use a Secure, HttpOnly, SameSite cookie for session
   tokens, or a short-lived in-memory token refreshed from the server.
3. **If secure storage is unavailable, data is encrypted with a key that also
   lives in secure storage** — not hardcoded, not in the same file, not derived
   from device-static values. Symmetric encryption with a keychain-held key is
   the baseline.
4. **Temp files for sensitive data are avoided**, or created with restrictive
   permissions (`0600`), written to a user-only directory, and deleted in a
   `finally` block — never left in `/tmp` with default perms.

Anchor — shape, not implementation:

```
# sensitive value → platform secure store
keychain.set("api_key", value)

# or, if you must use a file
key = keychain.get("file_enc_key") or keychain.generate_and_store("file_enc_key")
write(path, aead_encrypt(key, value), mode=0o600)
```

## Verification

- [ ] No credentials, tokens, or PII written to plain files or standard preference stores
- [ ] Platform secure storage API used (keyring, Keychain, EncryptedSharedPreferences)
- [ ] Temp files with sensitive data use secure deletion or are avoided entirely

## References

- CWE-312 ([Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html))
- CWE-922 ([Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html))
- [OWASP A02:2025 Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [OWASP Mobile M9:2024 Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/)
