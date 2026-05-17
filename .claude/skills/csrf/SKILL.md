---
name: csrf
description: Detects forms and state-changing endpoints missing CSRF protection. Use when
  writing HTML forms that submit POST/PUT/DELETE requests, configuring session
  cookies, or setting up CSRF middleware for web applications. Also invoke
  when disabling or bypassing CSRF protections in framework configuration.
---

# Cross-Site Request Forgery Check (A01:2025)

## What this checks

Protects against cross-site request forgery, where an attacker tricks an authenticated
user's browser into submitting a state-changing request the user did not intend.
Exploitation leads to unauthorized fund transfers, account takeover, or privilege
escalation.

## Vulnerable patterns

- `<form method="POST" action="/transfer">` — form with no CSRF token hidden field
- `@csrf_exempt` / `csrf().disable()` — framework CSRF protection explicitly disabled
- `Set-Cookie: session=abc123` — session cookie without `SameSite=Strict` or `SameSite=Lax`
- Express app with no `csurf` or `csrf-csrf` middleware registered

## Fix immediately

For each vulnerable call site, apply the appropriate control:

- **Django**: remove `@csrf_exempt`, ensure `django.middleware.csrf.CsrfViewMiddleware`
  is in `MIDDLEWARE`, include `{% csrf_token %}` in every POST form
- **Flask**: use `flask-wtf` with `CSRFProtect(app)`, include `{{ form.hidden_tag() }}`
  or `<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">`
- **Express**: add `csrf-csrf` or `csurf` middleware, pass token to templates via
  `res.locals`, include `<input type="hidden" name="_csrf" value="{{csrfToken}}">`
- **Spring**: remove `http.csrf().disable()` / `http.csrf(csrf -> csrf.disable())`,
  include `<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>`
  in Thymeleaf forms or use `th:action` (auto-includes token)
- **Go**: use `gorilla/csrf` or `justinas/nosurf` middleware, inject token via
  `csrf.TemplateField(r)` in templates
- **Rust (actix-web)**: use `actix-csrf` middleware, validate a token from a hidden
  form field against the session-bound value
- **Cookies**: always set `SameSite=Lax` (minimum) or `SameSite=Strict` on session
  cookies; add `Secure` and `HttpOnly` flags

**Secure pattern (Django):**

```python
# views.py — no @csrf_exempt, middleware enabled
from django.shortcuts import render

def transfer(request):
    if request.method == "POST":
        # token validated automatically by CsrfViewMiddleware
        process_transfer(request.POST["amount"], request.POST["to"])
        return redirect("/done")
    return render(request, "transfer.html")  # template has {% csrf_token %}
```

**Why this works:** The server generates a per-session (or per-request) token that an
attacker's cross-origin page cannot read. The middleware rejects any POST missing or
mismatching the token.

## Verification

Confirm the following properties hold (language-agnostic):

- [ ] Every state-changing endpoint (POST/PUT/PATCH/DELETE) is protected by a CSRF token validated server-side
- [ ] No framework CSRF middleware is disabled or bypassed (`@csrf_exempt`, `csrf().disable()`, `csrf: false`)
- [ ] Session cookies include `SameSite=Lax` or `SameSite=Strict` attribute
- [ ] CSRF tokens are not leaked in URLs, logs, or Referer headers
- [ ] API-only endpoints using token-based auth (Bearer header) may skip CSRF tokens, but cookie-authenticated endpoints must not

## References

- CWE-352 ([Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html))
- [OWASP A01:2025 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
