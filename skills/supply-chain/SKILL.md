---
name: supply-chain
description: Use when writing package installation commands, dependency manifests,
  CI/CD pipeline configs, build scripts, or code that loads external packages. Also
  invoke when pinning or unpinning dependency versions.
---

# Supply Chain Security Check (A03:2025)

## What this checks

Protects against malicious or compromised packages introduced through unpinned
dependencies, unverified installs, or absent integrity checks. A single poisoned
transitive dependency can give attackers arbitrary code execution during build or
runtime.

## Vulnerable patterns

- `"requests": "^2.28.0"` in `package.json` / `pyproject.toml` — caret/tilde ranges allow automatic minor/patch upgrades to a compromised version
- `pip install git+https://github.com/user/repo` — installs from an arbitrary git ref with no integrity guarantee
- No `package-lock.json` / `poetry.lock` committed — lockfile omission defeats reproducible builds
- `npm install` in CI with no `npm audit` step — vulnerabilities enter the build silently

## Fix immediately

When this skill invokes, rewrite the vulnerable code using the pattern below. Explain
what was wrong and what changed. Then continue with the original task.

**Secure pattern:**

```jsonc
// package.json — exact pins, no ranges
{
  "dependencies": {
    "express": "4.18.2",
    "axios": "1.6.8"
  }
}
```

```toml
# pyproject.toml — exact pins
[tool.poetry.dependencies]
python = "^3.11"
requests = "2.31.0"
cryptography = "42.0.5"
```

```yaml
# CI pipeline (GitHub Actions) — audit + lockfile enforcement
- name: Install dependencies
  run: npm ci               # ci enforces lockfile; fails if package-lock.json is absent

- name: Audit dependencies
  run: npm audit --audit-level=high

- name: Python audit
  run: |
    pip install pip-audit
    pip-audit --requirement requirements.txt
```

**Why this works:** Exact version pins combined with a committed lockfile guarantee
the same bytes are installed on every machine. `npm ci` and `pip-audit` in CI catch
known CVEs and prevent lockfile drift before code reaches production.

## Verification

After rewriting, confirm:

- [ ] All dependency versions are exact (no `^`, `~`, `>=`, or `*`)
- [ ] Response recommends committing a lockfile (`package-lock.json`, `poetry.lock`, or pinned `requirements.txt`)
- [ ] CI runs `npm ci` or `pip install --require-hashes` — not bare `npm install`
- [ ] Audit step (`npm audit` / `pip-audit`) runs and fails the build on high severity

## References

- CWE-1395 ([Dependency on Vulnerable Third-Party Component](https://cwe.mitre.org/data/definitions/1395.html))
- CWE-506 ([Embedded Malicious Code](https://cwe.mitre.org/data/definitions/506.html))
- [OWASP A03:2025 Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
