---
name: security-misconfiguration
description: Use when writing server configuration, setting environment variables,
  configuring CORS policies, enabling debug modes, setting up default credentials,
  or deploying application infrastructure. Also invoke when writing middleware that
  sets security headers.
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

When this skill invokes, rewrite the vulnerable code using the pattern below. Explain
what was wrong and what changed. Then continue with the original task.

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

After rewriting, confirm:

- [ ] `allow_origins` is an explicit list, not `"*"`, whenever credentials are included
- [ ] `debug` / `DEBUG` is read from an environment variable, defaulting to `False`
- [ ] All secrets are sourced from environment variables or a secrets manager
- [ ] Security headers middleware (`helmet` or equivalent) is registered before routes

## References

- CWE-16 ([Configuration](https://cwe.mitre.org/data/definitions/16.html))
- CWE-732 ([Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html))
- [OWASP A02:2025 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
