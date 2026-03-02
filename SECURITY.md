# Security Policy

## Scope

This policy covers vulnerabilities in Soundcheck itself — the plugin code, skill
definitions, and CI/CD infrastructure. It does not cover the security patterns that
Soundcheck *detects* (those are features, not vulnerabilities).

## Supported versions

Only the latest release on `main` is actively maintained.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately via [GitHub's private vulnerability reporting](https://github.com/thejefflarson/soundcheck/security/advisories/new).

Include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- A suggested fix if you have one

You should receive an acknowledgment within 72 hours. If the issue is confirmed, a fix
will be prioritized and a public advisory published after the patch is released.

## What counts as a vulnerability in Soundcheck?

- A skill that gives a false sense of security (claims to fix a pattern but leaves it vulnerable)
- A skill that rewrites code in a way that introduces a new vulnerability
- The static validator or smoke tests accepting a malformed/malicious skill
- The plugin manifest or install mechanism being abusable for supply chain compromise
- CI/CD pipeline that could be hijacked to publish a tampered release

## What does not count

- A skill triggering on code that turns out not to be vulnerable (false positive) — open a regular issue
- A skill missing coverage for a new attack pattern — use the threat nomination process in README.md
- Vulnerabilities in Claude itself or the Anthropic API
