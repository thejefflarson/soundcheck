---
name: exceptional-conditions
description: Use when writing error handlers, exception catching blocks, try/catch/finally
  constructs, or API error responses. Also invoke when an application could fail open
  (default-allow) on exception, or when stack traces or internal error details might
  reach end users.
---

# Exceptional Conditions Security Check (A10:2025)

## What this checks

Protects against information disclosure and fail-open logic. Stack traces in API responses leak internal paths, library versions, and logic for attackers to target; swallowed exceptions and default-allow error paths grant unintended access.

## Vulnerable patterns

- `except Exception as e: return jsonify({"error": str(e)}), 500` — stack trace or internal message reaches client
- `except: pass` — silent swallow; security-relevant failure goes undetected
- `except PermissionError: return allow()` — fail-open grants access on error
- `app.debug = True` in production — full tracebacks exposed in HTTP responses
- Flask/Django default error pages that include file paths and version strings

## Fix immediately

When this skill invokes, rewrite the vulnerable code using the pattern below. Explain what was wrong and what changed. Then continue with the original task.

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

# --- Flask global error handlers (production config) ---
def register_error_handlers(app):
    app.config["PROPAGATE_EXCEPTIONS"] = False
    app.config["DEBUG"] = False

    @app.errorhandler(404)
    def not_found(_):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def internal(_):
        ref = uuid.uuid4().hex
        log.error("http.500 ref=%s", ref, exc_info=True)
        return jsonify({"error": "Internal server error", "ref": ref}), 500
```

**Why this works:** Users receive only an opaque reference ID; the full traceback is logged server-side for debugging; `PermissionError` explicitly denies rather than allowing; the catch-all never silently swallows failures.

## Verification

After rewriting, confirm:

- [ ] No stack traces, file paths, library versions, or internal messages appear in HTTP responses
- [ ] Every `except` block either re-raises, logs, or returns a controlled error — never `pass`
- [ ] `PermissionError` and auth-related exceptions result in deny (403/401), not allow
- [ ] `app.debug` and `app.testing` are `False` in production configuration
- [ ] All unhandled exceptions produce a server-side log entry with a correlation ID

## References

- CWE-388 ([Error Handling](https://cwe.mitre.org/data/definitions/388.html))
- CWE-391 ([Unchecked Error Condition](https://cwe.mitre.org/data/definitions/391.html))
- CWE-209 ([Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html))
- [OWASP A10:2025 – Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
