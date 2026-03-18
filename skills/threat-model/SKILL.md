---
name: threat-model
description: Use when writing an implementation plan for a new feature, API endpoint,
  data pipeline, or system component. Also invoke when a plan introduces new trust
  boundaries, handles user-supplied data, adds authentication flows, or integrates
  external services.
---

# Threat Modeling Check (A06:2025)

## What this checks

Surfaces missing controls before implementation. Auth gaps, unprotected data flows,
and absent rate limiting are cheaper to fix in a plan than in code.

## Vulnerable patterns

- API endpoint planned with no authentication or authorization
- Data flow with PII or credentials and no encryption or access control
- Multi-step workflow with no rate limiting, lockout, or abuse-prevention step
- External service integration with no input validation, timeout, or error boundary
- Irreversible action (send email, delete record, charge card) with no confirmation step
- Security-relevant action (login, permission change, deletion) with no audit log step
- Operation with unbounded resource cost and no timeout or circuit breaker

## Fix immediately

Answer each question; add missing controls as explicit plan steps before continuing.

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
[ ] Does every user-facing endpoint have rate limits?
[ ] Any irreversible action without a confirmation gate?

REPUDIATION
[ ] Are auth events, permission changes, and deletions logged with actor and timestamp?
[ ] Are those logs write-only or tamper-evident?

RESOURCE LIMITS
[ ] Does each request have a compute or memory cost cap?
[ ] Are expensive operations protected by timeouts and circuit breakers?

EXTERNAL BOUNDARIES
[ ] Are inputs from external services validated before use?
[ ] Are timeouts and error responses defined for every external call?

```

## Verification

Confirm:

- [ ] Every new endpoint has explicit authentication and authorization
- [ ] Every PII data flow has an explicit encryption step
- [ ] Every user-facing endpoint has an explicit rate-limiting step
- [ ] No irreversible action proceeds without a confirmation or approval step
- [ ] Security-relevant actions are logged with actor and timestamp
- [ ] Expensive operations have explicit cost caps, timeouts, or circuit breakers

## References

- CWE-693 ([Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html))
- CWE-657 ([Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html))
- [OWASP A06:2025 Insecure Design](https://owasp.org/Top10/A06_2021-Insecure_Design/)
