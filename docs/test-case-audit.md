# Test Case Audit Checklist

Track the quality of each skill's test case. Update this file as gaps are fixed.

**Audit criteria:**
- [ ] Exercises every vulnerable pattern listed in `## Vulnerable patterns`
- [ ] Uses realistic, runnable code (not pseudocode)
- [ ] Comments mark each vulnerable line
- [ ] No secure-by-accident patterns that would prevent detection

---

## Status

| Skill | Test Case | All Patterns | Runnable | Comments | Notes |
|---|---|---|---|---|---|
| authentication-failures | `.py` | ✅ | ✅ | ✅ | All 4 patterns covered (MD5, hardcoded JWT secret, missing alg restriction, no session revocation) |
| broken-access-control | `.py` | ✅ | ✅ | ✅ | Uses mock `db` — realistic enough for detection |
| cryptographic-failures | `.py` | ✅ | ✅ | ✅ | MD5, insecure random, hardcoded key, ECB mode |
| exceptional-conditions | `.py` | ✅ | ✅ | ✅ | Stack trace exposure, fail-open, framework version leak |
| excessive-agency | `.py` | ✅ | ✅ | ✅ | Irreversible action, no dry-run, unrestricted scope |
| injection | `.py` | ✅ | ✅ | ✅ | Fixed 2025-02-25: added `eval()` pattern |
| insecure-design | `.py` | ✅ | ✅ | ✅ | Fixed 2026-02-26: added BUG comment on user-enumeration line |
| insecure-output-handling | `.js` | ✅ | ✅ | ✅ | innerHTML injection, LLM-generated code execution |
| insecure-plugin-design | `.py` | ✅ | ✅ | ✅ | No input constraints, no authz, path traversal |
| integrity-failures | `.py` | ✅ | ✅ | ✅ | Pickle, unsafe YAML, unsigned download |
| llm-supply-chain | `.py` | ✅ | ✅ | ✅ | Non-pinned revision ("main"), no hash verify |
| logging-failures | `.py` | ✅ | ✅ | ✅ | Fixed 2026-02-26: added CRLF injection example via `/profile` route |
| model-dos | `.py` | ✅ | ✅ | ✅ | No max_tokens, unbounded history, no rate limit |
| model-theft | `.py` | ✅ | ✅ | ✅ | No auth, no rate limit, token count exposure |
| overreliance | `.py` | ✅ | ✅ | ✅ | Medical diagnosis without disclaimer, auto-deploy without human gate |
| prompt-injection | `.py` | ✅ | ✅ | ✅ | User input in system prompt, RAG doc concatenation |
| security-misconfiguration | `.py` | ✅ | ✅ | ✅ | CORS wildcard+credentials, hardcoded creds, missing headers, debug mode |
| sensitive-disclosure | `.py` | ✅ | ✅ | ✅ | Full PII in system prompt, credentials in prompt, raw response echo |
| supply-chain | `.json` | ✅ | ✅ | n/a | JSON format prevents comments by design; detection relies on content (wildcard `*`, `curl\|bash`) |
| training-data-poisoning | `.py` | ✅ | ✅ | ✅ | Unvalidated scraping, no content filter, no integrity check |
| mcp-security | `.py` | ✅ | ✅ | ✅ | Hardcoded secret, shell injection, path traversal, unconstrained schema |
| oauth-implementation | `.py` | ✅ | ✅ | ✅ | alg:none, prefix redirect_uri, no state, hardcoded secret |
| rag-security | `.py` | ✅ | ✅ | ✅ | Arbitrary URL fetch, no length cap, undelimited context injection |

**Legend:** ✅ Pass  ⚠️ Needs attention  ❌ Failing

---

## Open Gaps

All gaps resolved as of 2026-02-26.

---

## Audit History

| Date | Auditor | Action |
|---|---|---|
| 2025-02-25 | Initial audit | Identified 3 gaps; fixed injection.py eval() pattern |
| 2026-02-26 | Update | Fixed all 3 gaps; added mcp-security, oauth-implementation, rag-security |
