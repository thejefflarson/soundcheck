---
name: security-misconfiguration
description: Use when writing server configuration, setting environment variables,
  configuring CORS policies, enabling debug modes, setting up default credentials,
  or deploying application infrastructure. Also invoke when writing security headers middleware.
---

# Security Misconfiguration Security Check (A02:2025)

## What this checks

Protects against insecure defaults, overly permissive policies, and missing hardening
that expose the application to cross-origin attacks, credential stuffing, and
information disclosure via error pages or debug endpoints.

## Vulnerable patterns

- `app.use(cors({ origin: "*", credentials: true }))` — wildcard CORS with credentials leaks cookies to any site
- `app.run(debug=True)` — Flask/Django debug mode exposes interactive traceback console in production
- `password = "admin"` hardcoded in source — default credential committed to version control
- Missing `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options` headers

## Fix immediately

When this skill invokes, flag the vulnerable code and explain the risk. Show the secure pattern below as a suggested fix. Then continue with the original task.

**Secure pattern:**

```python
# Strict CORS — Python (FastAPI / Starlette)
ALLOWED_ORIGINS = os.environ["CORS_ALLOWED_ORIGINS"].split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,   # never "*" when allow_credentials=True
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

# Production guard — Flask
assert os.environ.get("FLASK_ENV") != "production" or not app.debug, \
    "debug=True must not be set in production"

# Security headers middleware — Express.js (use helmet)
const helmet = require("helmet");
app.use(helmet());  # sets CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.

# Secrets from environment, never hardcoded
DB_PASSWORD = os.environ["DB_PASSWORD"]   # set in .env (gitignored) or secret manager
```

**Why this works:** Explicit origin allowlists prevent cross-site credential theft.
Helmet/security headers eliminate entire classes of browser-side attacks with a single
middleware call. Env-var secrets are never committed to version control.

## Verification

Confirm the following *properties* hold (language-agnostic):

- [ ] For every CORS configuration present in the code, if credentials are allowed then the allowed-origins value is an explicit allowlist — never a wildcard (`*`) or a reflected `Origin` header
- [ ] For every debug/development flag present in the code (`debug=True`, `DEBUG`, `RUST_LOG=trace`, verbose error responders, etc.), the value is sourced from an environment variable or config and defaults to off in production
- [ ] For every secret or credential present in the code (DB passwords, API keys, signing keys), the value is read from an environment variable or secrets manager — never a hardcoded literal or committed config file
- [ ] For every HTTP server or router present in the code, a security-headers layer (helmet, Django `SecurityMiddleware`, Rust `tower-http::set_header` / `SetResponseHeaderLayer`, Spring `HttpSecurity.headers()`, etc.) is registered before routes, setting at minimum `Strict-Transport-Security`, `X-Content-Type-Options`, and a framing/CSP control — unless the code comments explicitly document that an upstream proxy owns these headers

## References

- CWE-16 ([Configuration](https://cwe.mitre.org/data/definitions/16.html))
- CWE-732 ([Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html))
- [OWASP A02:2025 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
