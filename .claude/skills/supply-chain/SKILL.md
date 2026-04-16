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
- `"ai-fetch-helper": "^1.0.0"` in an AI-generated manifest — hallucinated package names are claimed by attackers before the developer notices (slopsquatting)

## Fix immediately

When this skill invokes, flag the vulnerable code and explain the risk. Show the secure pattern below as a suggested fix. Then continue with the original task.

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

- **Slopsquatting**: verify every AI-suggested package name exists in the registry before installing — `npm view <pkg>` / `pip index versions <pkg>`

**Why this works:** Exact version pins combined with a committed lockfile guarantee
the same bytes are installed on every machine. `npm ci` and `pip-audit` in CI catch
known CVEs and prevent lockfile drift before code reaches production.

## Verification

Confirm the response:

- [ ] Every direct dependency is pinned to an exact version — no `*`, `latest`, caret/tilde ranges, open comparators, or unpinned git branches/tags
- [ ] A lockfile is committed that records resolved transitive versions with content hashes or equivalent integrity checksums (e.g. `package-lock.json`, `pnpm-lock.yaml`, `poetry.lock`, `Cargo.lock`, `go.sum`, Maven dependency lock plugin output)
- [ ] CI installs dependencies with a command that fails if the lockfile does not match (e.g. `npm ci`, `pnpm install --frozen-lockfile`, `cargo build --locked`, `go mod verify`, `mvn dependency:verify`) — not a command that silently resolves fresh versions
- [ ] A vulnerability scanner runs in CI and fails the build on high-severity findings (any tool with a non-zero exit code suffices: `npm audit`, `pip-audit`, `cargo audit`, `nancy`, `trivy`, OWASP Dependency-Check)
- [ ] No install hooks, build scripts, or CI steps pipe remote content into a shell (`curl | bash`, `wget | sh`, `iwr | iex`)
- [ ] Any AI-generated or unrecognized package names are flagged for registry verification before install

## References

- CWE-1395 ([Dependency on Vulnerable Third-Party Component](https://cwe.mitre.org/data/definitions/1395.html))
- CWE-506 ([Embedded Malicious Code](https://cwe.mitre.org/data/definitions/506.html))
- [OWASP A03:2025 Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
