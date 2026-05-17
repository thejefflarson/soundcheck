---
name: logging-failures
description: Detects missing security event logs, logged secrets, and log injection through
  user input. Use when writing logging code, audit trails, error handlers that
  log, authentication event recording, or any code that writes security-
  relevant events. Also invoke when logging user inputs, API responses, or
  system actions that touch sensitive data.
---

# Security Logging and Monitoring Failures Security Check (A09:2025)

## What this checks

Protects the ability to detect and respond to attacks. Missing security event logs
leave breaches undetected; logging sensitive fields creates new data-exposure
vulnerabilities; CRLF injection lets attackers forge log entries.

## Vulnerable patterns

- `logger.info(f"Login attempt: {username} / {password}")` — password written to log
- No log entry on authentication failure — attacks go undetected
- `logger.debug(request.json())` — full request body with PII or tokens
- `logger.info(user_input)` — CRLF injection forges log lines (`\n[CRITICAL] admin logged in`)
- Unstructured string logs that can't be parsed or alerted on by SIEM tools

## Fix immediately

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **Every security-relevant decision point emits exactly one log record.**
   Authentication outcomes, authorization outcomes, privileged actions — no branch
   silently exits. A successful login and a failed login should both produce a
   record; a missing failure log is as bad as no logging at all.
2. **Credential-like fields never appear as values.** Names like `password`, `token`,
   `secret`, `authorization`, `api_key`, `session`, `credit_card`, `ssn` are either
   omitted or redacted before the log call. Do this at the logger, not at every
   call site — a forgotten call site is a guaranteed leak.
3. **Every user-controlled string passes through a CRLF/newline stripping step
   before reaching the log sink** — including fields that "look safe" like
   usernames, and including any dedicated `actor`/`subject`/`user_id` parameter
   (not just fields passed through `**kwargs`). A username with
   `\n[CRITICAL] admin logged in` forges log lines whether it arrives as a
   positional argument or a kwarg.
4. **Records are structured key/value data (JSON, structured fields) — not an
   interpolated message string.** A SIEM has to regex-parse a message string, and
   regex-parsers miss things attackers can exploit.
5. **Each record carries an event-type identifier and an actor identifier.** The
   actor is a non-null field naming who or what triggered the event — a user id,
   session id, `"anonymous"`, or `"system"` for server-initiated jobs. Never silently
   omitted.

Anchor — shape, not implementation:

```
log.security_event("auth.failure", actor=username)        # CRLF-stripped, no password
log.security_event("auth.success", actor=user.id)
log.security_event("authz.denied", actor=user.id, resource=id)
```

## Verification

Confirm these properties hold (language-agnostic):

- [ ] Every security-relevant decision point in the rewritten code (authentication outcome, authorization outcome, privileged action) emits exactly one log record — no branch silently exits without logging
- [ ] Credential-like field names (password, passwd, token, secret, authorization, api_key, session) never appear as values in any log record — they are either omitted or replaced with a redaction marker before the log call
- [ ] Every user-controlled string value reaching a log sink passes through a CRLF/newline stripping step — no field is interpolated raw, including ones that "look safe" like usernames and including dedicated `actor`/`subject`/`user_id` parameters (not only fields in `**kwargs`)
- [ ] Log records are emitted as structured key/value data (JSON object, structured logger fields, or equivalent) — not as a single interpolated message string that a SIEM would have to regex-parse
- [ ] Each record carries an event-type identifier and an actor identifier — a non-null field naming who or what triggered the event (user id, session id, `"anonymous"`, or `"system"` for server-initiated jobs). The actor field is never silently omitted from any security event.

## References

- CWE-117 ([Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html))
- CWE-223 ([Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html))
- CWE-532 ([Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html))
- [OWASP A09:2025 – Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)
