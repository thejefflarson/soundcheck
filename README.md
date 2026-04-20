# Soundcheck

Automated security checks for Claude Code. 45 skills covering injection, authentication,
cryptography, access control, LLM-specific threats, and more — drawn from OWASP, CWE, and
real-world vulnerability patterns. Skills auto-invoke when Claude writes vulnerable code,
flag the issue, explain the fix, and continue with your original task.

No configuration needed. No user intervention required.

---

## Security Review

### Interactive: `/security-review`

Type `/security-review` in any Claude Code session for a full security audit.
Works best with sonnet or opus — the skill orchestrates subagents internally.

### CI / PR gate: [`soundcheck-action`](https://github.com/thejefflarson/soundcheck-action)

Run Soundcheck's security review on every pull request using the
[Soundcheck GitHub Action](https://github.com/thejefflarson/soundcheck-action).
It comments a severity-ranked findings table on the PR and, when findings are
rewritable, commits the fixes back to the branch.

```yaml
name: Security Review
on: [pull_request]
permissions:
  contents: write
  pull-requests: write
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: thejefflarson/soundcheck-action@v1
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

See the [action README](https://github.com/thejefflarson/soundcheck-action)
for inputs (`max-files`, `model`, `base-branch`) and outputs
(`pr-url`, `findings-count`).

### Local CLI

For one-off scans from your checkout, run the review script directly. PR-scoped:

```bash
python scripts/security-review-action.py --repo-dir . --diff-base main
```

Full-repo scan (sonnet recommended, ~10 min, ~$4):

```bash
python scripts/security-review-action.py --repo-dir . --full-repo --model sonnet
```

---

## Install

```bash
claude plugin marketplace add thejefflarson/soundcheck
claude plugin install soundcheck
```

After installation, all 45 skills are active in every Claude Code session. Claude will
automatically invoke the relevant skill whenever it detects vulnerable code patterns.

**Try it without installing** (current session only):

```bash
claude --plugin-dir /path/to/soundcheck
```

---

## How it works

Each skill has a `description` field that tells Claude when to invoke it. When you ask
Claude to write code matching that description, Claude:

1. Invokes the skill automatically (visible in tool use)
2. Rewrites the vulnerable section with a secure alternative
3. Explains what was wrong and what the fix establishes
4. Continues with your original task

You do not need to ask Claude to check for security issues. Soundcheck runs in the
background on every relevant code-writing task.

---

## Trigger Reference

| Code pattern | Skill invoked | OWASP |
|---|---|---|
| Authorization checks, resource ownership, IDOR, SSRF | `broken-access-control` | A01:2025 |
| Server config, CORS, debug flags, security headers, secrets | `security-misconfiguration` | A02:2025 |
| `npm install`, `pip install`, dependency manifests, CI/CD pipelines | `supply-chain` | A03:2025 |
| Encryption, password hashing, random token generation, TLS config | `cryptographic-failures` | A04:2025 |
| SQL queries, shell commands, templates with user input, `eval`, ORM raw queries | `injection` | A05:2025 |
| Rate limiting, login flows, business logic, multi-step workflows | `insecure-design` | A06:2025 |
| Login, sessions, JWT, password storage, MFA, API key management | `authentication-failures` | A07:2025 |
| Deserialization, pickle/yaml load, software update verification, CI artifacts | `integrity-failures` | A08:2025 |
| Logging, audit trails, error handlers that log, security event recording | `logging-failures` | A09:2025 |
| Error handlers, try/catch, API error responses, exception propagation | `exceptional-conditions` | A05:2025 |
| LLM prompt construction with user input, RAG pipelines, system prompts | `prompt-injection` | LLM01:2025 |
| Rendering LLM output to UI, executing LLM-generated code, downstream LLM output use | `insecure-output-handling` | LLM02:2025 |
| Fine-tuning pipelines, dataset ingestion, training data from external sources | `training-data-poisoning` | LLM03:2025 |
| LLM input limits, inference backends, chatbot request handling, token budgets | `model-dos` | LLM04:2025 |
| Loading pre-trained models, model registries, third-party LLM providers | `llm-supply-chain` | LLM05:2025 |
| Sending PII/secrets to LLM, system prompts with sensitive data, LLM memory | `sensitive-disclosure` | LLM06:2025 |
| LLM tool definitions, function schemas, plugin access controls | `insecure-plugin-design` | LLM07:2025 |
| Autonomous agents, LLM-triggered write/delete/send actions, multi-step pipelines | `excessive-agency` | LLM08:2025 |
| Displaying LLM output as fact, LLM-driven consequential decisions, no human review | `overreliance` | LLM09:2025 |
| Inference API endpoints, model access controls, rate limiting on model serving | `model-theft` | LLM10:2025 |
| MCP server definitions, tool schemas, tool handlers with file/shell/network access | `mcp-security` | LLM07:2025 |
| OAuth2/OIDC flows, JWT validation, redirect URI handling, token endpoints | `oauth-implementation` | A07:2025 |
| RAG pipelines, vector store ingestion, external document retrieval for LLM context | `rag-security` | LLM01:2025 |
| Implementation plans for features, APIs, or components touching user data or auth | `threat-model` | A06:2025 |
| Storing credentials/tokens/PII to local files, prefs stores, SQLite, or temp dirs | `insecure-local-storage` | A02:2025 |
| URL scheme handlers, exported Android activities, IPC sockets, XPC service handlers | `ipc-security` | A01:2025 |
| Agent-to-agent calls, subagent spawning, multi-agent pipelines | `multi-agent-trust` | LLM08:2025 |
| User-supplied strings to LLM with Unicode control chars, homoglyphs, RTL override | `token-smuggling` | LLM01:2025 |
| ORM create/update from raw request body, spread/merge without field allowlist | `mass-assignment` | API3:2023 |
| HTML forms with POST/PUT/DELETE, session cookies, CSRF middleware config | `csrf` | A01:2025 |
| File upload handlers, multipart form data, user-supplied filenames | `file-upload` | A04:2025 |
| HTTP requests to user-supplied URLs, webhook callbacks, URL preview features | `ssrf` | A10:2025 |
| File open/read/write with paths from user input, static file serving by name | `path-traversal` | A01:2025 |
| Third-party API calls, external response parsing, webhook/callback integration | `unsafe-api-consumption` | API10:2023 |
| Regular expressions on user input, input validation patterns | `redos` | CWE-1333 |
| Check-then-act on shared state, balance updates without locks, TOCTOU | `race-condition` | CWE-362 |
| Redirect to URL from request params, login "return to" URLs | `open-redirect` | CWE-601 |
| JS/TS deep merge, Object.assign, lodash merge with user input | `prototype-pollution` | CWE-1321 |
| API keys, passwords, tokens as string literals in source | `hardcoded-secrets` | CWE-798 |
| GraphQL schemas without depth limits, introspection in production | `graphql-security` | CWE-400 |
| MongoDB/NoSQL queries with user input, operator injection | `nosql-injection` | CWE-943 |
| User input in HTTP response headers, CRLF injection | `header-injection` | CWE-113 |

### On-Demand

| Command | What it does |
|---|---|
| `/security-review` | Full OWASP sweep — subagent pipeline with threat model, hotspot mapping, parallel auditors, design review, attack-chain analysis |

---

## Optional: Reinforce triggers in your CLAUDE.md

Add this snippet to `~/.claude/CLAUDE.md` if you want to make the triggers explicit for
all projects, not just those with the plugin:

```markdown
## Security

When writing code, always invoke the soundcheck plugin skills for any code involving:
authentication, authorization, cryptography, SQL/shell/template construction, error
handling, logging, deserialization, LLM API calls, or agent workflows.
```

---

## Contributing

1. Read `CLAUDE.md` for dev conventions
2. Copy `docs/skill-template.md` to `.claude/skills/<name>/SKILL.md`
3. Fill in all fields — no TODO placeholders
4. Add a test case to `docs/test-cases/<name>.<ext>`
5. Run the static validator — must pass with no violations:
   ```bash
   python scripts/validate-skills.py --skill <name>
   ```
6. Run the smoke test to confirm Claude detects the vulnerability:
   ```bash
   python scripts/smoke-test-skills.py --skill <name> --verbose
   ```

Skills must be under 600 words, include CWE references, and have a concrete runnable
code rewrite in the "Fix immediately" section (or `## Procedure` for analysis skills).
Test cases should cover multiple languages where the vulnerable API differs.
See `docs/test-case-audit.md` for the current audit status.

## Nominating a new threat

The threat landscape moves faster than OWASP's publication cycle. To nominate an
emerging threat for Soundcheck coverage:

1. Open a GitHub Issue using the **[Threat Nomination](.github/ISSUE_TEMPLATE/threat-nomination.md)** template
2. Include at least one real-world source (CVE, writeup, or incident)
3. Paste a short code snippet showing the vulnerable pattern — if you can't show code, the threat may not be detectable yet

Nominations are auto-labeled `threat-candidate` and reviewed each quarter. The full
backlog lives in [`docs/threat-radar.md`](docs/threat-radar.md), which tracks 14+
threats across four status tiers: `watching`, `candidate`, `in-progress`, and `shipped`.

---

## Measured effect

A paired smoke test (`scripts/smoke-test-skills.py`) reviews 130 intentionally
vulnerable fixtures twice — once with Soundcheck's skill content loaded as
system context, once with a neutral security-reviewer system prompt — then
scores both reviews against the skill's own verification criteria.

Across two model strengths (after excluding judge-parse failures):

| Model | Rows | Plugin full-pass | Bare full-pass | Gap | +plugin | −plugin | Wilcoxon p |
|---|---|---|---|---|---|---|---|
| Haiku | 126 | **77%** (98/126) | 40% (51/126) | **+37pts** | 67 | 11 | < 1e-6 |
| Sonnet | 130 | **90%** (117/130) | 58% (75/130) | **+32pts** | 48 | 7 | < 1e-4 |

Bare baseline climbs 18pts moving haiku → sonnet (stronger base model), but plugin
stays ~30pts ahead regardless. The same effect holds at both capability tiers.
Methodology and why Wilcoxon in
[`docs/smoke-test-methodology.md`](docs/smoke-test-methodology.md).

### External validation

Smoke runs on our own fixtures and criteria, so it could in principle be overfit
to the exact patterns we wrote. Two independent checks:

**[SecurityEval](https://github.com/s2e-lab/SecurityEval)** — 104 vulnerable Python
samples across ~50 CWEs, authored by academic researchers with ground-truth labels
(`scripts/benchmark-securityeval.py --with-bare`, haiku):

| | Plugin | Bare |
|---|---|---|
| Full-pass | 104/104 (100%) | 104/104 (100%) |
| Detection | 100% | 100% |
| Fix | 100% | 100% |

Zero discordant pairs. SecurityEval samples are CWE-tagged one-file snippets that a
generic "security reviewer" prompt catches trivially, so both arms saturate at
ceiling. This confirms the plugin *does not regress* on external fixtures and rules
out overfitting-induced breakage, but the benchmark can't discriminate further.
Plugin review latency median is 15.2s vs bare 17.7s — the narrower focus of a
skill-loaded review is slightly faster, not slower.

**Real-world OWASP projects** — 13 vulnerable files pinned at specific commits from
OWASP Juice Shop (TypeScript) and OWASP PyGoat (Python), covering SQL/NoSQL
injection, broken access control, SSRF, path traversal, weak crypto, unsafe
deserialization, and auth (`scripts/benchmark-realworld.py`, haiku, plugin arm):

| | Value |
|---|---|
| Full-pass | 12/13 (92%) |
| Detection | 100% |
| Fix | 96% |

Single miss: open-redirect in `juice-shop/routes/redirect.ts` — the vulnerability
was detected but the proposed fix didn't fully address the allowlist-substring bug.

---

## License

MIT
