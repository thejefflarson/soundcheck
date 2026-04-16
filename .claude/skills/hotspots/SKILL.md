---
name: hotspots
description: Use when the user asks to identify security-sensitive areas in a codebase,
  map the attack surface, or find where a security review should focus. Also invoke
  when asked to triage or prioritize security effort across a repository.
---

# Security Hotspot Analysis (A06:2025)

## What this checks

Maps security-sensitive code so reviewers know where to focus. Missed hotspots mean
entire attack surfaces go unreviewed.

## Vulnerable patterns

This skill does not target a single antipattern — it identifies areas where
vulnerabilities are statistically most likely:

- Route/endpoint handlers accepting external input
- Authentication, session, and credential management code
- Authorization and role-checking middleware
- Database queries and ORM calls
- File I/O with user-influenced paths
- Cryptographic operations and secret loading
- Serialization/deserialization of untrusted data
- HTTP client calls to third-party services

## Procedure

**Step 1 — Architecture summary.** Read `README*`, `ARCHITECTURE*`, `docs/`,
`SECURITY*`, and `CONTRIBUTING*`. Produce a 3–6 bullet summary: what the system
does, major components, trust boundaries, auth model, data stores, external
integrations. Without this framing you cannot tell a critical boundary from a
helper.

**Step 2 — Hotspot scan.** Skip `node_modules/`, `.venv/`, `dist/`, `build/`,
`target/`.

**For each file, look for:**

```
TRUST BOUNDARIES — route handlers, CLI arg parsing, file upload
  endpoints, WebSocket/SSE handlers, IPC listeners
AUTH & SESSIONS — login/logout, signup, password reset, JWT
  creation/validation, OAuth callbacks, API key checks
ACCESS CONTROL — role/permission checks, object-level lookups by ID
DATA LAYER — SQL/ORM queries, deserialization (pickle, YAML, marshal),
  file read/write with dynamic paths
CRYPTO & SECRETS — encrypt/decrypt, hashing, key generation, TLS
  config, secret loading from env/vault/config
EXTERNAL CALLS — HTTP clients, LLM API calls, email/SMS/payment,
  cloud SDK usage
```

**Output format:**

| Priority | Category | File | Lines | What |
|----------|----------|------|-------|------|

Priority: **Critical** (auth, crypto, direct user input), **High** (access control,
data persistence), **Medium** (logging, external calls, config).

After producing the table, recommend which Soundcheck skills to run against each
hotspot category.

## Verification

- [ ] Architecture summary produced from available documentation
- [ ] All route/endpoint entry points identified
- [ ] Authentication and authorization code located
- [ ] Database and file I/O hotspots listed
- [ ] Crypto and secret-handling code flagged
- [ ] Output table produced with priorities and line ranges

## References

- CWE-693 ([Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html))
- CWE-657 ([Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html))
- [OWASP A06:2025 Insecure Design](https://owasp.org/Top10/A06_2021-Insecure_Design/)
