---
name: security-misconfiguration
description: Detects insecure defaults, overly permissive CORS, exposed debug endpoints,
  and missing security headers. Use when writing server configuration, setting
  environment variables, configuring CORS policies, enabling debug modes,
  setting up default credentials, or deploying application infrastructure.
  Also invoke when writing security headers middleware.
---

# Security Misconfiguration Security Check (A02:2025)

## What this checks

Protects against insecure defaults, overly permissive policies, and missing hardening
that expose the application to cross-origin attacks, credential stuffing, and
information disclosure via error pages or debug endpoints.

## Vulnerable patterns

- `app.use(cors({ origin: "*", credentials: true }))` — wildcard CORS with credentials leaks cookies to any site
- `app.run(debug=True)` — Flask/Django debug mode exposes interactive traceback console in production
- `ALLOWED_HOSTS = ["*"]` — permissive host validation in production. For hardcoded secrets, see `hardcoded-secrets`
- Missing `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options` headers

## Fix immediately

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **CORS with `allow_credentials=true` uses an explicit origin allowlist** —
   never `*`, never a reflected `Origin` header. The wildcard-plus-credentials
   combination hands every site on the web cookie-authenticated access to your
   API; browsers block it in spec, but misconfigured middleware still ships it.
2. **Debug and verbose-error flags default to off in production.** `debug=True`,
   `DEBUG`, `RUST_LOG=trace`, and equivalent switches come from environment or
   config — never hardcoded `True`. Production-only guards (`assert not
   app.debug`) make a misconfigured deploy fail loudly.
3. **Every HTTP server registers a security-headers layer** (helmet, Django
   `SecurityMiddleware`, `tower-http` `SetResponseHeaderLayer`, Spring
   `HttpSecurity.headers()`) before routes. Baseline: `Strict-Transport-Security`,
   `X-Content-Type-Options: nosniff`, and a framing or CSP control. An upstream
   proxy may own these instead — but only if that ownership is documented.
4. **Host / origin validation uses an explicit allowlist**, not `*` or empty
   defaults. Django `ALLOWED_HOSTS`, trusted-origin lists, and CSRF-trusted
   origins are all attacker-reachable when unset.

Anchor — shape, not implementation:

```
app.use(cors({ origins: ALLOWED_ORIGINS, credentials: true }))   # not "*"
app.use(security_headers_middleware())                             # HSTS + nosniff + frame
assert env("NODE_ENV") != "production" or not DEBUG                # fail loudly
```

## Verification

Confirm the following *properties* hold (language-agnostic):

- [ ] For every CORS configuration present in the code, if credentials are allowed then the allowed-origins value is an explicit allowlist — never a wildcard (`*`) or a reflected `Origin` header
- [ ] For every debug/development flag present in the code (`debug=True`, `DEBUG`, `RUST_LOG=trace`, verbose error responders, etc.), the value is sourced from an environment variable or config and defaults to off in production
- [ ] For every HTTP server or router present in the code, a security-headers layer (helmet, Django `SecurityMiddleware`, Rust `tower-http::set_header` / `SetResponseHeaderLayer`, Spring `HttpSecurity.headers()`, etc.) is registered before routes, setting at minimum `Strict-Transport-Security`, `X-Content-Type-Options`, and a framing/CSP control — unless the code comments explicitly document that an upstream proxy owns these headers

## References

- CWE-16 ([Configuration](https://cwe.mitre.org/data/definitions/16.html))
- CWE-732 ([Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html))
- [OWASP A02:2025 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
