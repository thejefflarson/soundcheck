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

- Direct dependencies declared with floating ranges — `*`, `latest`, caret, tilde, open comparators, or unpinned git branches/tags — that silently pull in compromised releases
- Installs from arbitrary git refs, tarball URLs, or local paths with no integrity guarantee
- No lockfile committed, or CI install command that silently resolves fresh versions instead of failing on lockfile drift
- CI with no vulnerability scanner, or a scanner whose findings do not fail the build
- Install hooks, build scripts, or CI steps that pipe remote content into a shell
- AI-generated manifests containing hallucinated package names that attackers can claim (slopsquatting)

## Fix immediately

Flag the vulnerable code, explain the risk, and suggest a fix establishing these
properties. Translate to the package manager and CI system of the audited file — use
that ecosystem's documented lockfile, frozen-install command, and audit tool; do not
import a recipe from a different ecosystem.

1. **Every direct dependency is pinned to an exact version.** No floating ranges, no unpinned git branches or tags. A floating range silently pulls in the next compromised release; an exact pin means a human decides when to move.
2. **A lockfile is committed** that records resolved transitive versions with content hashes or equivalent integrity checksums. CI installs with a frozen-lockfile command that fails on drift, not a silent-resolve command.
3. **A vulnerability scanner runs in CI and fails the build on high-severity findings.** Any tool that exits non-zero works. A scanner that reports but does not fail the build is advisory, not a gate.
4. **No install hook, build script, or CI step pipes remote content into a shell.** Every instance replaces the whole supply chain with whatever the server decides to serve today.
5. **AI-suggested or unrecognized package names are verified in the registry before install** — slopsquatted typosquats are a growing vector in AI-generated manifests.

## Verification

Confirm the response:

- [ ] Every direct dependency is pinned to an exact version — no `*`, `latest`, caret/tilde ranges, open comparators, or unpinned git branches/tags
- [ ] A lockfile is committed that records resolved transitive versions with content hashes or equivalent integrity checksums
- [ ] CI installs dependencies with a command that fails if the lockfile does not match — not a command that silently resolves fresh versions
- [ ] A vulnerability scanner runs in CI and fails the build on high-severity findings (any tool with a non-zero exit code suffices)
- [ ] No install hooks, build scripts, or CI steps pipe remote content into a shell (`curl | bash`, `wget | sh`, `iwr | iex`)
- [ ] Any AI-generated or unrecognized package names are flagged for registry verification before install

## References

- CWE-1395 ([Dependency on Vulnerable Third-Party Component](https://cwe.mitre.org/data/definitions/1395.html))
- CWE-506 ([Embedded Malicious Code](https://cwe.mitre.org/data/definitions/506.html))
- [OWASP A03:2025 Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
