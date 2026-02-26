---
name: broken-access-control
description: Use when writing code that checks authorization, enforces resource ownership,
  handles IDOR (object-level authorization), processes server-side requests to external
  URLs, or implements access control middleware. Also invoke when writing API endpoints
  that retrieve or modify user-specific resources.
---

# Broken Access Control Security Check (A01:2025)

## What this checks

Protects against unauthorized resource access caused by missing ownership checks or
role enforcement. Exploitation leads to horizontal/vertical privilege escalation and,
via SSRF, internal network exposure.

## Vulnerable patterns

- `resource = db.get(request.params.id)` — fetches any record without verifying caller owns it
- `app.delete("/admin/user/:id", handler)` — admin endpoint with no role middleware
- `fetch(user_supplied_url)` — server-side request to a caller-controlled URL (SSRF)
- `if user.id == id: return resource` — ownership check placed after the data is already fetched and potentially acted on

## Fix immediately

When this skill invokes, rewrite the vulnerable code using the pattern below. Explain
what was wrong and what changed. Then continue with the original task.

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

# SSRF allowlist — Python
ALLOWED_HOSTS = {"api.trusted.com", "cdn.trusted.com"}
from urllib.parse import urlparse
def safe_fetch(url: str) -> bytes:
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        raise ValueError(f"Host not allowed: {host}")
    return httpx.get(url).content
```

**Why this works:** The ownership check binds the DB row to the authenticated caller
before returning data. The SSRF allowlist prevents the server from being used as a
proxy to internal or arbitrary external hosts.

## Verification

After rewriting, confirm:

- [ ] Every resource fetch is followed immediately by an owner/role assertion
- [ ] Admin routes have role middleware applied at the router level, not inline
- [ ] No user-controlled URL reaches `fetch`/`requests.get` without allowlist validation
- [ ] 404 (not 403) is returned on ownership mismatch to prevent enumeration

## References

- CWE-284 ([Improper Access Control](https://cwe.mitre.org/data/definitions/284.html))
- CWE-918 ([Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html))
- [OWASP A01:2025 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
