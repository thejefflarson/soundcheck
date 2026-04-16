---
name: logging-failures
description: Use when writing logging code, audit trails, error handlers that log,
  authentication event recording, or any code that writes security-relevant events.
  Also invoke when logging user inputs, API responses, or system actions that touch
  sensitive data.
---

# Security Logging and Monitoring Failures Security Check (A09:2025)

## What this checks

Protects the ability to detect and respond to attacks. Missing security event logs leave breaches undetected; logging sensitive fields creates new data-exposure vulnerabilities; CRLF injection lets attackers forge log entries.

## Vulnerable patterns

- `logger.info(f"Login attempt: {username} / {password}")` — password written to log
- No log entry on authentication failure — attacks go undetected
- `logger.debug(request.json())` — full request body with PII or tokens
- `logger.info(user_input)` — CRLF injection forges log lines (`\n[CRITICAL] admin logged in`)
- Unstructured string logs that can't be parsed or alerted on by SIEM tools

## Fix immediately

When this skill invokes, rewrite the vulnerable code using the pattern below. Explain what was wrong and what changed. Then continue with the original task.

**Secure pattern:**

```python
import logging
import json
import re
from typing import Any

class StructuredLogger:
    def __init__(self, name: str):
        self._log = logging.getLogger(name)

    _SCRUB = frozenset({"password", "passwd", "token", "secret",
                        "authorization", "api_key", "credit_card", "ssn"})

    @staticmethod
    def _sanitize_crlf(value: str) -> str:
        return re.sub(r"[\r\n]", " ", str(value))

    def _scrub(self, data: dict[str, Any]) -> dict[str, Any]:
        return {
            k: "[REDACTED]" if k.lower() in self._SCRUB
               else self._sanitize_crlf(str(v))
            for k, v in data.items()
        }

    def security_event(self, event: str, **fields: Any) -> None:
        record = {"event": event, **self._scrub(fields)}
        self._log.info(json.dumps(record))

log = StructuredLogger(__name__)

def login(username: str, password: str) -> dict:
    user = db.get_user(username)
    if not user or not verify_password(password, user.password_hash):
        log.security_event("auth.failure", username=username)   # no password
        return {"error": "Invalid credentials"}, 401
    log.security_event("auth.success", user_id=user.id)
    return {"token": create_session(user)}, 200

def deny_access(user_id: str, resource: str) -> None:
    log.security_event("authz.denied", user_id=user_id, resource=resource)
```

**Why this works:** Structured JSON is parseable by SIEM tools; scrubbing blocks credential leakage; CRLF sanitization prevents log injection; every auth decision (success and failure) produces a durable audit record.

## Verification

After rewriting, confirm the following *properties* hold (language-agnostic):

- [ ] Every security-relevant decision point in the rewritten code (authentication outcome, authorization outcome, privileged action) emits exactly one log record — no branch silently exits without logging
- [ ] Credential-like field names (password, passwd, token, secret, authorization, api_key, session) never appear as values in any log record — they are either omitted or replaced with a redaction marker before the log call
- [ ] Every user-controlled string value reaching a log sink passes through a CRLF/newline stripping step — no field is interpolated raw, including ones that "look safe" like usernames
- [ ] Log records are emitted as structured key/value data (JSON object, structured logger fields, or equivalent) — not as a single interpolated message string that a SIEM would have to regex-parse
- [ ] Each record carries an event-type identifier and a subject identifier (user id, session id, or explicit "anonymous") — the subject field is never silently omitted

## References

- CWE-117 ([Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html))
- CWE-223 ([Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html))
- CWE-532 ([Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html))
- [OWASP A09:2025 – Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)
