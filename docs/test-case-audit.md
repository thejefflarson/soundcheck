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
| threat-model | `.md` | ✅ | ✅ | n/a | Plan with missing auth, no rate limits, unprotected PII flow, no confirmation gate |
| insecure-local-storage | `.py` | ✅ | ✅ | ✅ | Plaintext credentials to file, NSUserDefaults, localStorage |
| ipc-security | `.js` | ✅ | ✅ | ✅ | URL scheme handler with no origin check, exported intent, unauthenticated socket |
| multi-agent-trust | `.py` | ✅ | ✅ | ✅ | No subagent identity check, inherited permissions, unsanitized task passthrough |
| token-smuggling | `.py` | ✅ | ✅ | ✅ | RTL override, homoglyph, zero-width chars in user-supplied prompt |
| security-review | `.py` | n/a | n/a | n/a | On-demand skill; invoked via /security-review, not pattern-matched |
| pr-review | `.py` | n/a | n/a | n/a | On-demand skill; invoked via /pr-review or `security-review-action.py --diff-base`, not pattern-matched |
| contract-review | `.py` | n/a | n/a | n/a | On-demand skill; invoked via /contract-review or `contract-review.py`, not pattern-matched |
| memory-api-misuse | `.c` | ✅ | ✅ | ✅ | 6 bugs: unchecked malloc, realloc-in-place leak, double-free on error path, mutex without init, fopen without O_CLOEXEC, mmap MAP_FAILED unchecked |
| crypto-library-misuse | `.py` | ✅ | ✅ | ✅ | 5 bugs: static AEAD nonce, ECDSA caller-supplied k, length-extensible hash-MAC, non-constant-time MAC compare, exception-type distinguisher |
| privilege-handling | `.c` | ✅ | ✅ | ✅ | 5 bugs: setuid drop-order, system() with PATH trust, tmpnam race, /tmp open without O_NOFOLLOW, missing umask |
| concurrency-correctness | `.go` | ✅ | ✅ | ✅ | 5 bugs: lock held across HTTP I/O, AB-BA lock order, ready flag without sync, lock-then-sleep, unbuffered channel send under lock |
| numeric-trust-boundary | `.c` | ✅ | ✅ | ✅ | 6 bugs: signed-char sign-extension, atoi-returns-0 as auth ID, width-truncated bounds check, multiplication wraparound, negative index, divide-by-zero |

**Legend:** ✅ Pass  ⚠️ Needs attention  ❌ Failing

---

## Open Gaps

Some older skills not yet entered in the table above (csrf, file-upload,
ssrf, path-traversal, etc.) — their test cases pass the validator and
the smoke test, but coverage rows haven't been written. Low-priority
backfill.

---

## Audit History

| Date | Auditor | Action |
|---|---|---|
| 2025-02-25 | Initial audit | Identified 3 gaps; fixed injection.py eval() pattern |
| 2026-02-26 | Update | Fixed all 3 gaps; added mcp-security, oauth-implementation, rag-security |
| 2026-03-18 | Update | Added insecure-local-storage, ipc-security, multi-agent-trust, token-smuggling, security-review |
| 2026-05-23 | Update | Added pr-review + contract-review orchestrators; added 5 systems-software skills (memory-api-misuse, crypto-library-misuse, privilege-handling, concurrency-correctness, numeric-trust-boundary) |
