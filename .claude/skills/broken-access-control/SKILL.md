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

When this skill invokes, flag the vulnerable code and explain the risk. Show the secure pattern below as a suggested fix. Then continue with the original task.

- Return 404 (not 403) on **ownership** failures — prevents resource enumeration. Use this in every language: Python `HTTPException(status_code=404)`, Java `ResponseStatusException(HttpStatus.NOT_FOUND)`, Go `http.NotFound(w, r)`, Rust `StatusCode::NOT_FOUND`. Role-missing failures on privileged routes may use 403 since the route itself is public information.
- Apply role checks at the router/middleware level, not as inline if-checks in handler bodies.

**Secure pattern:**

```python
# Ownership check — Python / SQLAlchemy
def get_document(doc_id: int, current_user: User) -> Document:
    doc = db.session.get(Document, doc_id)
    if doc is None or doc.owner_id != current_user.id:
        raise HTTPException(status_code=404)  # 404, not 403, to avoid enumeration
    return doc

# Role middleware — Express.js
const requireRole = (role) => (req, res, next) => {
    if (!req.user?.roles.includes(role)) return res.status(403).end();
    next();
};
app.delete("/admin/user/:id", requireRole("admin"), deleteUserHandler);

```

**Why this works:** The ownership check binds the DB row to the authenticated caller
before returning data. Role middleware applied at the **router level** (as a named
middleware function passed to the route) is more reliable than inline checks: it
cannot be accidentally omitted from a new handler, and it is visible at a glance in
the route definition.

## Verification

Confirm the following *properties* hold (language-agnostic):

- [ ] Every resource lookup by caller-supplied identifier is gated by an ownership or role predicate before the resource is returned, mutated, or acted on — regardless of whether the check lives in a handler, interceptor, filter, annotation, decorator, or middleware
- [ ] Privileged routes enforce role membership through a reusable, centrally-declared mechanism (middleware, filter chain, annotation, decorator, policy) attached at the route/controller declaration — not via ad-hoc `if` checks inside individual handler bodies
- [ ] **Ownership** (per-instance IDOR) failures return an indistinguishable "not found" response (e.g. HTTP 404) rather than a distinct "forbidden" response, to prevent resource enumeration. Role-missing failures on a privileged route (e.g. `/admin/*`) may return 403 because the route itself is public knowledge — only the *instance-level* check needs to hide behind 404.

## References

- CWE-284 ([Improper Access Control](https://cwe.mitre.org/data/definitions/284.html))
- CWE-862 ([Missing Authorization](https://cwe.mitre.org/data/definitions/862.html))
- CWE-863 ([Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html))
- CWE-918 ([Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html))
- [OWASP A01:2025 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
