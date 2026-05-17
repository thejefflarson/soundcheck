---
name: supply-chain
description: Detects unpinned dependencies, unverified package installs, and missing
  integrity checks in build pipelines. Use when writing package installation
  commands, dependency manifests, CI/CD pipeline configs, build scripts, or
  code that loads external packages. Also invoke when pinning or unpinning
  dependency versions.
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

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **Every direct dependency is pinned to an exact version.** No `*`, no
   `latest`, no caret/tilde ranges, no open comparators, no unpinned git
   branches or tags. A floating range silently pulls in the next compromised
   release; an exact pin means a human decides when to move.
2. **A lockfile is committed** that records resolved transitive versions with
   content hashes — `package-lock.json`, `pnpm-lock.yaml`, `poetry.lock`,
   `Cargo.lock`, `go.sum`, or the Maven lock plugin output. CI installs with
   a frozen-lockfile command (`npm ci`, `pnpm install --frozen-lockfile`,
   `cargo build --locked`, `go mod verify`) that fails on drift, not a
   silent-resolve command.
3. **A vulnerability scanner runs in CI and fails the build on high-severity
   findings.** Any tool that exits non-zero works — `npm audit`, `pip-audit`,
   `cargo audit`, `trivy`, OWASP Dependency-Check. A scanner that reports but
   doesn't fail the build is advisory, not a gate.
4. **No install hook, build script, or CI step pipes remote content into a
   shell.** `curl | bash`, `wget | sh`, `iwr | iex` — every instance replaces
   the whole supply chain with whatever the server decides to serve today.
5. **AI-suggested or unrecognized package names are verified in the registry
   before install** — slopsquatted typosquats are a real and growing vector
   in AI-generated manifests. `npm view <pkg>` / `pip index versions <pkg>`
   catches them.

Anchor — shape, not implementation:

```
# manifest: "express": "4.18.2"       # exact, not ^4.18.0
# CI:
npm ci                                # fails if lockfile missing / drifted
npm audit --audit-level=high          # non-zero exit gates the build
# forbidden: curl https://… | bash
```

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
