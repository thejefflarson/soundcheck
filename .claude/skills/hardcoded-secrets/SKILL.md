---
name: hardcoded-secrets
description: Detects API keys, passwords, tokens, and credentials embedded directly in
  source code. Use when writing code that contains API keys, passwords,
  tokens, connection strings, or private keys as string literals. Also invoke
  when embedding credentials in configuration files, environment setup
  scripts, or test fixtures that could be committed to version control.
---

# Hardcoded Secrets Security Check (CWE-798)

## What this checks

Protects against credentials, API keys, and secrets embedded directly in source code.
Hardcoded secrets end up in version control history, build artifacts, and container
images. Once committed, secrets are effectively public — even if the commit is reverted,
the secret remains in git history.

## Vulnerable patterns

- `API_KEY = "sk_live_abc123..."` — production API key in source
- `password = "admin123"` — hardcoded password
- `conn_str = "postgresql://user:pass@host/db"` — credentials in connection string
- `private_key = "-----BEGIN RSA PRIVATE KEY-----\n..."` — embedded private key
- `token = "ghp_xxxx..."` — GitHub personal access token in code

## Fix immediately

Flag the hardcoded secret and explain the risk. Then suggest a fix that establishes
these properties:

1. **Secrets are loaded from outside the source tree.** Environment variable,
   secrets manager (AWS Secrets Manager, HashiCorp Vault, 1Password), KMS, or OS
   keystore. No string literal that resembles a real credential appears in source
   — not in code, not in config files, not in test fixtures.
2. **Missing secrets fail loudly at load time, not silently at first use.** A
   `getenv("API_KEY")` with no fallback, a required-field check, or an early
   fatal log guarantees a misconfigured deploy crashes immediately rather than
   running with an empty string that mysteriously fails later.
3. **Test fixtures use obviously fake values** — `test_key_DO_NOT_USE`,
   `sk_test_FAKE`, `changeme` — that cannot be mistaken for production
   credentials and will never unlock a real service if leaked.
4. **Rotation does not require a code change.** If rotating the credential means
   editing source and redeploying, the secret is effectively hardcoded even if
   it's technically loaded through a constant. Rotation happens by updating the
   external store and restarting.

Anchor — shape, not implementation:

```
API_KEY = require_env("API_KEY")       # fail fast if missing
DB_URL  = secrets_manager.get("db/primary")
# no string literal matching /sk_live_|ghp_|AKIA[0-9A-Z]{16}|-----BEGIN/ in source
```

## Verification

- [ ] No string literal in the code resembles a production API key, password, token, private key, or connection string with embedded credentials
- [ ] All credentials are loaded from environment variables, secrets managers, or encrypted configuration — never from source code
- [ ] Test fixtures use obviously fake values (e.g., `test_key_DO_NOT_USE`) that cannot be mistaken for real credentials

## References

- CWE-798 ([Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html))
- CWE-259 ([Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html))
