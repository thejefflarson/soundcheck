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
TRUST BOUNDARIES
[ ] What inputs cross a trust boundary? Are they validated before use?
[ ] Does any step pass user-supplied data to a database, shell, or template?

DATA FLOWS
[ ] Does any step persist or transmit PII, credentials, or secrets?
[ ] Are those flows encrypted in transit and at rest?

ACCESS CONTROL
[ ] Does every new endpoint require authentication?
[ ] Are permissions checked at the resource level, not just the route?

ABUSE PREVENTION
[ ] Are rate limits defined for every new user-facing endpoint?
[ ] Does any step take an irreversible action without a confirmation gate?

EXTERNAL BOUNDARIES
[ ] Are inputs from external services validated before use?
[ ] Are timeouts and error responses defined for every external call?
```

**Why this works:** Answering these before writing code ensures the reactive Soundcheck
skills have something secure to enforce — and catches whole missing layers (no auth,
no encryption) that code-level pattern matching cannot see.

## Verification

After updating the plan, confirm:

- [ ] Every new endpoint has an explicit authentication and authorization step
- [ ] Every data flow involving PII has an explicit encryption step
- [ ] Every user-facing endpoint has an explicit rate-limiting step
- [ ] No irreversible action proceeds without a confirmation or approval step

## References

- CWE-693 ([Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html))
- CWE-657 ([Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html))
- [OWASP A06:2025 Insecure Design](https://owasp.org/Top10/A06_2021-Insecure_Design/)
