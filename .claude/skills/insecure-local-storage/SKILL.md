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

Replace unprotected storage with platform-secure equivalents:

```python
# Python: OS keychain via keyring
import keyring
keyring.set_password("myapp", "api_key", secret)
secret = keyring.get_password("myapp", "api_key")
```

```kotlin
// Android: EncryptedSharedPreferences
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
val prefs = EncryptedSharedPreferences.create(
    context, "secure_prefs", masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM)
```

```swift
// iOS: Keychain
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "api_key",
    kSecValueData as String: secretData]
SecItemAdd(query as CFDictionary, nil)
```

**Why this works:** Platform-managed secure storage encrypts at rest and enforces
process-level access control, preventing other apps and backup restores from reading
secrets.

## Verification

- [ ] No credentials, tokens, or PII written to plain files or standard preference stores
- [ ] Platform secure storage API used (keyring, Keychain, EncryptedSharedPreferences)
- [ ] Temp files with sensitive data use secure deletion or are avoided entirely

## References

- CWE-312 ([Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html))
- CWE-922 ([Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html))
- [OWASP A02:2025 Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [OWASP Mobile M9:2024 Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/)
