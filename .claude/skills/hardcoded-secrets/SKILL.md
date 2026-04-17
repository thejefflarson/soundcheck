---
name: hardcoded-secrets
description: Use when writing code that contains API keys, passwords, tokens, connection
  strings, or private keys as string literals. Also invoke when embedding credentials
  in configuration files, environment setup scripts, or test fixtures that could be
  committed to version control.
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

Flag the hardcoded secret and explain the risk. Show the secure pattern below as a
suggested fix. Then continue with the original task.

**Secure pattern:**

```python
# Python — read from environment
import os
API_KEY = os.environ["API_KEY"]  # fails fast if not set
DB_URL = os.environ["DATABASE_URL"]

# For optional secrets with safe defaults
DEBUG_KEY = os.environ.get("DEBUG_KEY", "")  # empty, not a real key
```

```go
// Go — environment variables
apiKey := os.Getenv("API_KEY")
if apiKey == "" {
    log.Fatal("API_KEY not set")
}
```

```javascript
// Node.js — environment or secrets manager
const apiKey = process.env.API_KEY;
if (!apiKey) throw new Error("API_KEY required");
```

**Why this works:** Environment variables keep secrets out of source code and version
control. They can be set differently per environment (dev/staging/prod) and rotated
without code changes. For production systems, use a secrets manager (AWS Secrets
Manager, HashiCorp Vault, 1Password) instead of raw env vars.

## Verification

- [ ] No string literal in the code resembles a production API key, password, token, private key, or connection string with embedded credentials
- [ ] All credentials are loaded from environment variables, secrets managers, or encrypted configuration — never from source code
- [ ] Test fixtures use obviously fake values (e.g., `test_key_DO_NOT_USE`) that cannot be mistaken for real credentials

## References

- CWE-798 ([Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html))
- CWE-259 ([Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html))
