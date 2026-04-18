---
name: broken-access-control
description: Use when writing code that checks authorization, enforces resource ownership,
  handles IDOR (object-level authorization), processes server-side requests to external
  URLs, or implements access control middleware.
---

# Broken Access Control Security Check (A01:2025)

## What this checks

Protects against unauthorized resource access caused by missing ownership checks or
role enforcement. Exploitation leads to horizontal/vertical privilege escalation.
For SSRF (server-side request forgery), see the dedicated `ssrf` skill.

## Vulnerable patterns

- `resource = db.get(request.params.id)` — fetches any record without verifying caller owns it
- `app.delete("/admin/user/:id", handler)` — admin endpoint with no role middleware
- `if user.id == id: return resource` — ownership check placed after the data is already fetched and potentially acted on

## Fix immediately

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **Every resource lookup by caller-supplied identifier is gated before the resource
   is returned, mutated, or acted on.** The gate binds the row to the authenticated
   caller — an ownership predicate for per-instance access, or a role predicate for
   role-scoped access. The check can live in a handler, interceptor, filter, annotation,
   decorator, or middleware — anywhere, as long as it runs before the data is used.
2. **Privileged routes enforce role membership through a reusable, centrally-declared
   mechanism** (middleware, filter chain, annotation, decorator, policy) attached at
   the route or controller declaration. Ad-hoc `if role != "admin"` checks inside
   handler bodies are brittle — they can be forgotten on a new route and they're
   invisible at a glance.
3. **Ownership failures return an indistinguishable "not found" response (HTTP 404).**
   Returning 403 leaks that the resource exists. Role-missing failures on a privileged
   route (e.g. `/admin/*`) may still return 403 — the route itself is public
   knowledge, so only the *instance-level* check needs to hide behind 404.

Anchor — shape, not implementation:

```
# resource fetch — ownership gate before returning data
row = db_get(Resource, id)
if row is None or row.owner_id != caller.id:
    return 404                        # not 403 — hide existence

# privileged route — role gate as route-level middleware
router.delete("/admin/user/:id", require_role("admin"), delete_user)
```

## Verification

Confirm these properties hold (language-agnostic):

- [ ] Every resource lookup by caller-supplied identifier is gated by an ownership or role predicate before the resource is returned, mutated, or acted on — regardless of whether the check lives in a handler, interceptor, filter, annotation, decorator, or middleware
- [ ] Privileged routes enforce role membership through a reusable, centrally-declared mechanism (middleware, filter chain, annotation, decorator, policy) attached at the route/controller declaration — not via ad-hoc `if` checks inside individual handler bodies
- [ ] Ownership (per-instance IDOR) failures return an indistinguishable "not found" response (e.g. HTTP 404) rather than a distinct "forbidden" response, to prevent resource enumeration. Role-missing failures on a privileged route may use 403 because the route itself is public knowledge

## References

- CWE-284 ([Improper Access Control](https://cwe.mitre.org/data/definitions/284.html))
- CWE-862 ([Missing Authorization](https://cwe.mitre.org/data/definitions/862.html))
- CWE-863 ([Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html))
- CWE-918 ([Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html))
- [OWASP A01:2025 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
