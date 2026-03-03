---
name: threat-modeling
description: Use when writing an implementation plan for a new feature, API endpoint,
  data pipeline, or system component. Also invoke when a plan introduces new trust
  boundaries, handles user-supplied data, adds authentication flows, or integrates
  external services.
---

# Threat Modeling Check (A06:2025)

## What this checks

Surfaces missing security controls at design time, before implementation begins.
Auth gaps, unprotected data flows, and absent rate limiting are cheaper to catch in
a plan than in code — and invisible to the reactive skills until it's too late.

## Vulnerable patterns

- Plan adds an API endpoint with no mention of authentication or authorization
- New data flow introduces PII or credentials with no mention of encryption or access control
- Multi-step workflow has no rate limiting, lockout, or abuse-prevention step
- External service integration has no input validation, timeout, or error-boundary step
- Irreversible action (send email, delete record, charge card) with no confirmation step

## Fix immediately

When this skill invokes, before finalizing the plan, answer each question below.
Add any missing controls as explicit steps in the plan, then continue.

**Security design checklist:**

```
[ ] What inputs cross a trust boundary? Are they validated?
[ ] Does any step persist or transmit PII? Is it encrypted at rest and in transit?
[ ] Does every new endpoint require authentication and resource-level authorization?
[ ] Are rate limits defined for every user-facing endpoint?
[ ] Does any step take an irreversible action without a confirmation gate?
[ ] Are inputs from external services validated? Are timeouts defined?
```

**Why this works:** Answering these before writing code ensures the reactive Soundcheck
skills have something secure to enforce — and catches whole missing layers (no auth,
no encryption) that code-level pattern matching cannot see.

## Verification

After updating the plan, confirm:

- [ ] Every new endpoint has an explicit authentication and authorization step
- [ ] At least one PII data flow lacking encryption is identified and an encryption control added
- [ ] Every user-facing endpoint has an explicit rate-limiting step
- [ ] At least one irreversible action is identified and a confirmation or approval step added

## References

- CWE-693 ([Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html))
- CWE-657 ([Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html))
- [OWASP A06:2025 Insecure Design](https://owasp.org/Top10/A06_2021-Insecure_Design/)
