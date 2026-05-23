# Soundcheck

Automated security checks for Claude Code. 52 skills covering injection, authentication,
cryptography, access control, LLM-specific threats, and more — drawn from OWASP, CWE, and
real-world vulnerability patterns. Skills auto-invoke when Claude writes vulnerable code,
flag the issue, explain the fix, and continue with your original task.

No configuration needed. No user intervention required.

---

## Three review modes

Auto-invoking skills cover what Claude writes mid-task. On top of that,
Soundcheck has three on-demand review modes for when you want to scan
existing code. Each mode answers a different question:

| Mode | When to use | Time | Cost | Catches |
|---|---|---|---|---|
| **`pr-review`** | Every pull request, in CI | ≤1 min | a few cents | Critical/High OWASP issues in the diff |
| **`security-review`** | Nightly CI, monthly audit, or manual deep scan | ~20 min | ~$4 | All severities, whole repo, with attack chains |
| **`contract-review`** | Nightly/weekly CI, pre-release scan, or after a major refactor | ~30 min | ~$10–20 | Bugs where a function does less than its callers assume — caller/callee invariant gaps |

If you're not sure which to run: gate every pull request on `pr-review`,
schedule `security-review` nightly or weekly, and add `contract-review`
on a slower cadence (weekly or pre-release) once your obvious bugs are
fixed. All three can run in CI — `pr-review` is the only one that's
appropriate for *per-PR* feedback because of the latency budget.

### 1. `pr-review` — fast PR gate

Reviews only the files changed in your branch. Reports Critical and High
findings. Fast and cheap enough to run on every pull request.

**In CI** — use the [Soundcheck GitHub Action](https://github.com/thejefflarson/soundcheck-action):

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

The action comments a severity-ranked findings table on the PR and, when
findings are auto-fixable, commits the fixes back to the branch.

**Locally** — run the same review script from your checkout:

```bash
python scripts/security-review-action.py --repo-dir . --diff-base main
```

### 2. `security-review` — full repo audit

Reviews the whole repo. Reports all severities. Use it for a monthly
deep scan or before a release.

**In Claude Code** — just type `/security-review` in any Claude Code
session. Works best with sonnet or opus.

**Locally** — run the script directly:

```bash
python scripts/security-review-action.py --repo-dir . --full-repo --model sonnet
```

On a large monorepo, `--full-repo` can push past typical per-request limits.
If it hits a timeout, fall back to `--diff-base main` against a smaller
branch.

### 3. `contract-review` — deep audit for subtler bugs

Reviews each public function in your codebase by reading what callers
expect from it and checking whether the body actually guarantees that.
Designed to find bugs that single-pass review misses — the kind where
function-A and function-B each look fine in isolation, but together
they have a gap. Typical shapes: a helper whose body is weaker than
its name suggests, a check that fails open on an unusual input, a
caller that trusts a return value beyond what the body actually
guarantees.

Run it locally:

```bash
python scripts/contract-review.py --repo-dir . --model opus
```

It prints a findings table to stdout. Each row names the function
being audited, where it's called from, the contract gap, and a
concrete attacker scenario.

**Findings are hypothesis-grade.** Contract-review surfaces *candidate*
bugs that a maintainer should read carefully — not confirmed CVEs.
In our testing, building actual proof-of-concept code for the findings
produced a meaningful false-positive rate: some claims described real
code patterns, but the path to exploitation broke at a downstream
check that the audit hadn't traced. Treat each finding as "read this
carefully and write a PoC before filing."

#### What it catches and what it misses

We benchmarked contract-review against six small-to-medium open-source
projects, each pinned to a commit just before a publicly-disclosed
CVE landed. We asked one question per repo: *did the tool surface the
specific function the maintainers fixed?*

| Repo size | Bug location | Found |
|---|---|---|
| 15K files (Java) | public auth handler | ✓ Critical, round 1 |
| 250 files (C) | function at top of binary's main path | ✓ Critical |
| 4.5K files (C) | deep codec internal helper | ✗ — not seeded |
| 78 files (C) | static internal helper | ✗ — not seeded |
| 6.8K files (Java) | run drifted to scanning Soundcheck itself, not the target | — invalid |
| 320K LOC (C++) | wall-clock timeout before completion | — invalid |

**Hit rate on valid runs: 2/4.** Both hits were on *public entry-point
functions* — the seeder picks those up reliably. Both misses were on
*static internal helpers* — the seeder's heuristic ("functions called
from ≥2 sites on a security-relevant path") doesn't reliably reach
them. The bugs in those misses were memory-safety class, somewhat
out of contract-review's design scope.

Known limitations:
- Repos larger than ~200K LOC currently exceed the 30-minute single-LLM-call
  budget. Architecturally fixable by batching into multiple calls.
- The seeder is biased toward public API surface and away from internal
  helpers, which means deep-codec / kernel-style bugs are harder to find.
- On two of seven benchmark runs the tool drifted from auditing the target
  repo to auditing Soundcheck's own scripts (visible via the plugin's
  own source tree). Watch for findings that reference unexpected paths.

#### Contract review vs full security review

We ran both `security-review` and `contract-review` against the same four
small-to-medium repos (the two that fit in budget on opus). The two modes
have *disjoint* strengths:

| Repo (target bug class) | `security-review` | `contract-review` |
|---|---|---|
| Java auth handler (auth-bypass via control flow) | ✗ missed | ✓ Critical |
| C SMTP relay (command injection via DNS) | ✓ Critical | ✓ Critical |
| C codec (integer overflow → memory write) | ✗ missed | ✗ missed |
| C transfer engine (uninit-stack info leak) | ✗ missed | ✗ missed |

`security-review` is the broad OWASP/LLM-Top-10 sweep — high finding volume
(20-40 per repo), great fit for SQL-injection / shell-injection / cryptographic
choice / authentication-flow class bugs. `contract-review` is the focused
caller/callee-invariant auditor — lower volume (5-15 per repo), catches the
bugs `security-review`'s pattern matchers don't have a template for. The
one overlap (command injection) is where both modes have native skill
coverage; everywhere else they catch different things or both miss.

For memory-safety bugs neither mode reliably finds, run an instrumented
build (`-fsanitize=address,undefined`), a fuzzer (libFuzzer, OSS-Fuzz),
and a static analyzer (`clang-tidy`, CodeQL) alongside Soundcheck. Mature
deterministic tools own that territory.

### Non-Anthropic providers (Bedrock, Vertex)

Soundcheck shells out to `claude -p --model <X>`, so whatever model string
the `claude` CLI accepts, Soundcheck accepts. For AWS Bedrock or Google
Vertex, the model argument alone isn't enough — the CLI needs
provider-selection env vars before it will route the call correctly:

```bash
# Bedrock
export CLAUDE_CODE_USE_BEDROCK=1
export AWS_REGION=us-east-1
# plus AWS credentials (SSO, IAM role, or access keys)

python scripts/security-review-action.py --repo-dir . --diff-base main \
  --model arn:aws:bedrock:us-east-1:...:application-inference-profile/...
```

```bash
# Vertex
export CLAUDE_CODE_USE_VERTEX=1
export CLOUD_ML_REGION=us-east5
export ANTHROPIC_VERTEX_PROJECT_ID=your-gcp-project
```

Without those env vars, `claude -p --model <ARN>` will hang or silently fail
and Soundcheck will surface a timeout. The script runs a short preflight
call before the real review to catch this class of misconfiguration fast.

---

## Install

```bash
claude plugin marketplace add thejefflarson/soundcheck
claude plugin install soundcheck
```

After installation, all 52 skills are active in every Claude Code session. Claude will
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
| `/pr-review` | Fast Critical/High gate over the files changed in your branch — usually run by the [GitHub Action](https://github.com/thejefflarson/soundcheck-action), not by hand |
| `/security-review` | Full OWASP sweep — subagent pipeline with threat model, hotspot mapping, parallel auditors, design review, attack-chain analysis |
| `/contract-review` | Deep audit that reads each public function alongside every caller and flags places where the body delivers less than the callers expect |

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

## Does it actually work?

Short answer: yes, reliably. Here's how we know.

### Head-to-head test

We have 130 deliberately broken code fixtures — things like a Flask login route
with hardcoded passwords, a SQL query built by string concatenation, a file upload
endpoint with no size limit. Each fixture has a checklist of what a thorough
security review should catch and fix.

For every fixture, we ask Claude to review it two ways: once with Soundcheck
loaded, once with just a generic "be a security reviewer" prompt. A second Claude
call, the judge, scores both reviews against the checklist. "Full pass" means
every checklist item is satisfied.

| Model | With Soundcheck | Plain Claude | Difference |
|---|---|---|---|
| Haiku (fast/cheap) | **77%** full-pass | 40% | **+37 points** |
| Sonnet (slower/better) | **90%** full-pass | 58% | **+32 points** |

When the two reviews disagree on a fixture, Soundcheck wins roughly **6 times out
of 7**. The size of the gap is similar across both model strengths, so this isn't
"Soundcheck only helps weak models" — loading the plugin raises the floor at every
tier we tested.

### External validation

Smoke-test fixtures are written by us, so the result above could in principle
favor patterns we had in mind. Two independent checks:

**[SecurityEval](https://github.com/s2e-lab/SecurityEval)** — 104 vulnerable Python
samples published by academic security researchers with ground-truth CWE labels.
Both arms scored **100% detection and 100% fix** here. These snippets are obvious
enough that plain Claude already catches everything, so this benchmark can't
discriminate further — but it confirms Soundcheck doesn't *break* anything on
external code it wasn't designed against.

**Real OWASP projects** — 13 vulnerable files pinned from OWASP Juice Shop
(TypeScript) and OWASP PyGoat (Python), covering SQL injection, broken access
control, SSRF, path traversal, weak crypto, unsafe deserialization, and auth.
Soundcheck caught and fully fixed **12 of 13 (92%)**, with 100% detection across
all 13. The one miss — an open-redirect in Juice Shop's `redirect.ts` — was
detected but only partially fixed.

### How long does a review take?

Running Soundcheck's full three-stage review pipeline (hotspot map → threat
model → security review) against four open-source projects at pinned commits
(`scripts/benchmark-eval.py`):

| Repo | Language | Haiku | Sonnet |
|---|---|---|---|
| [redash](https://github.com/getredash/redash) | Python | **6.1 min** | 17.3 min |
| [gitea](https://github.com/go-gitea/gitea) | Go | **6.2 min** | 6.6 min + timeout on security-review* |
| [cal.com](https://github.com/calcom/cal.com) | TypeScript | **8.7 min** | 25.7 min |
| [vaultwarden](https://github.com/dani-garcia/vaultwarden) | Rust | **5.7 min** | 14.7 min |
| **Totals** | | **26.6 min review / 52.5 min wall** | **64.3 min review / 111.9 min wall** |

\* Sonnet's full-audit security-review on gitea exceeded the 20-minute
per-call timeout. Haiku completed gitea in 2 minutes. Sonnet is the better
auditor when it finishes but cal.com and gitea push the limits of a single
review call — for those codebases, the PR-scoped `--diff-base` mode (which
only reviews changed files) is the practical option.

Practical guidance:

- **Haiku is fast enough for PR-gate use** — typical diff-scoped reviews
  complete in 1–2 minutes. Full-repo audits average ~7 minutes per repo.
- **Sonnet is for monthly/quarterly deep scans** — higher-quality findings
  but 3–4× the time per call, and hits timeouts on the largest codebases.
- **Soundcheck itself doesn't add review latency.** On the SecurityEval
  paired run we measured plugin-loaded reviews at 15.2s median vs plain
  Claude at 17.7s median — the skill's narrower focus finishes slightly
  faster, not slower.

### Details for the curious

- Statistical test (Wilcoxon signed-rank on per-fixture score differences):
  p < 1e-6 on haiku, p < 1e-4 on sonnet. Methodology in
  [`docs/smoke-test-methodology.md`](docs/smoke-test-methodology.md).
- Reproduce with `python scripts/smoke-test-skills.py` (paired, ~2h on haiku)
  or `python scripts/benchmark-securityeval.py --with-bare` / `python
  scripts/benchmark-realworld.py` for the external runs.

---

## License

MIT
