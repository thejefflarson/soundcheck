---
name: exceptional-conditions
description: Use when writing error handlers, exception catching blocks, try/catch/finally
  constructs, or API error responses. Also invoke when an application could fail open
  on exception, or when stack traces might reach end users.
---

# Exceptional Conditions Security Check (A05:2025)

## What this checks

Protects against information disclosure and fail-open logic. Stack traces in API responses leak internal paths, library versions, and logic for attackers to target; swallowed exceptions and default-allow error paths grant unintended access.

## Vulnerable patterns

- `except Exception as e: return jsonify({"error": str(e)}), 500` — stack trace or internal message reaches client
- `except: pass` — silent swallow; security-relevant failure goes undetected
- `except PermissionError: return allow()` — fail-open grants access on error
- `app.debug = True` in production — full tracebacks exposed in HTTP responses
- Flask/Django default error pages that include file paths and version strings

## Fix immediately

When this skill invokes, flag the vulnerable code and explain the risk. Show the secure pattern below as a suggested fix. Then continue with the original task.

**Secure pattern:**

```python
import logging
import uuid
import traceback
from functools import wraps
from flask import jsonify

log = logging.getLogger(__name__)

# --- Generic user-facing error; details logged server-side only ---
def _error_response(status: int, ref_id: str) -> tuple:
    return jsonify({"error": "An unexpected error occurred", "ref": ref_id}), status

def safe_handler(fn):
    """Decorator: fail-closed with opaque client errors and full server-side logging."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        ref = uuid.uuid4().hex
        try:
            return fn(*args, **kwargs)
        except PermissionError:
            # Fail-closed: deny access, never allow on exception
            log.warning("authz.error ref=%s", ref, exc_info=True)
            return _error_response(403, ref)
        except ValueError as exc:
            log.info("validation.error ref=%s msg=%s", ref, exc)
            return jsonify({"error": "Invalid input", "ref": ref}), 400
        except Exception:
            # Catch-all: log full traceback server-side, return nothing internal
            log.error("unhandled.exception ref=%s\n%s", ref, traceback.format_exc())
            return _error_response(500, ref)
    return wrapper
```

**Why this works:** Users receive only an opaque reference ID; the full traceback is logged server-side for debugging; `PermissionError` explicitly denies rather than allowing; the catch-all never silently swallows failures.

## Verification

Confirm the following *properties* hold (language-agnostic):

- [ ] No stack trace, file path, library version, exception message, or other internal detail reaches the client response body — only a generic message and opaque reference ID
- [ ] Every catch/except/recover block takes a definite action (re-raise, log, or return a controlled error) — no silently swallowed exceptions
- [ ] Authorization and permission failures produce a deny response (HTTP 401/403, or equivalent error return) — never a success or fall-through that grants access
- [ ] If the code configures a server or application entry point, debug/verbose-error flags are explicitly set to off (e.g. Flask `app.debug=False`, Spring `include-stacktrace=never`, Go `gin.ReleaseMode`). Skip this criterion for library-level code or handlers that have no configuration surface
- [ ] Every unhandled exception produces a server-side log entry containing a correlation ID (UUID or equivalent) that matches the opaque reference returned to the client

## References

- CWE-388 ([Error Handling](https://cwe.mitre.org/data/definitions/388.html))
- CWE-391 ([Unchecked Error Condition](https://cwe.mitre.org/data/definitions/391.html))
- CWE-209 ([Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html))
- [OWASP A05:2025 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
