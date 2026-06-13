# Soundcheck

Automated security checks for Claude Code. 52 skills covering injection,
authentication, cryptography, access control, LLM-specific threats, and
more — drawn from OWASP, CWE, and real-world vulnerability patterns.
When Claude is about to write vulnerable code, the matching skill
auto-invokes, prompts Claude to flag the issue and rewrite it safely,
and hands the turn back.

---

## Install

```bash
claude plugin marketplace add thejefflarson/soundcheck
claude plugin install soundcheck
```

All 52 skills are active in every Claude Code session after install. To
try without installing (current session only):

```bash
claude --plugin-dir /path/to/soundcheck
```

---

## How you'll use it

### Automatic reviews after each edit

Soundcheck reviews every diff the moment Claude finishes writing it.
When something looks risky, the findings surface to Claude as a system
reminder once Claude Code wakes the session — usually within a turn
or two, sometimes longer if the review queue is backed up. From there
Claude can fix the code, push back, or note the issue for you. The
review happens in the background; you never block on it.

A one-shot haiku triage decides whether the diff warrants a full
review, so most turns cost ~$0.003. Only diffs that plausibly introduce
a vulnerability trigger the full `pr-review` — a few cents when it
fires.

Enabled by default. To disable, export `SOUNDCHECK_AUTO_REVIEW=false`
in your shell before launching Claude Code. See
[docs/auto-review.md](docs/auto-review.md) for the staged flow, full
cost table, and limitations.

### On demand: three review modes for existing code

When you want to scan existing code — a PR diff, a whole repo before a
release, or a deep audit before shipping — reach for one of these:

| Mode | When | Time | Cost | Catches |
|---|---|---|---|---|
| **`/pr-review`** | Every pull request, in CI | 1–2 min | a few cents | Critical/High OWASP in the diff |
| **`/security-review`** | Nightly CI or monthly audit | ~10 min on haiku, ~25 min on sonnet | ~$4 on sonnet | All severities, whole repo, attack chains |
| **`/contract-review`** | Pre-release or after big refactor | ~30 min | ~$15–20 per repo on opus | Bugs where a function does less than callers assume |

Rule of thumb: gate every PR on `pr-review`, schedule `security-review`
nightly or weekly, and add `contract-review` on a slower cadence once
the obvious bugs are out of the way.

#### `pr-review` — the CI gate

> **Security note:** `pr-review` passes untrusted repository content into an LLM
> context. Prompt-injection mitigations are instruction-level only — a crafted
> file in the PR could influence the model's output. Treat a clean gate result as
> "no obvious Critical/High findings," not as a guarantee of correctness. Do not
> use `pr-review` output as the sole gate for high-stakes merges; pair it with
> human review for security-sensitive changes.

Use the [Soundcheck GitHub Action](https://github.com/thejefflarson/soundcheck-action):

```yaml
name: Security Review
on: [pull_request]
# contents:write is only required when autofix is enabled (apply-rewrites: 'true').
# For read-only review, downgrade to contents:read.
# Do NOT trigger on fork PRs — GITHUB_TOKEN from a fork cannot write back to the
# base repo, and untrusted fork code runs with write permissions.
permissions:
  contents: write        # needed only for autofix commits; use contents:read otherwise
  pull-requests: write   # needed to post the findings comment
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

The action posts a severity-ranked findings table to the PR. Auto-fix
(committing LLM-generated changes back to the branch) stays off by
default; opt in with `apply-rewrites: 'true'`. Before turning it on in
CI, gate the resulting commits behind branch-protection rules and human
review — the action ships no approval gate of its own. To preview the
changes without committing, run the script locally:

```bash
python scripts/security-review-action.py --repo-dir . --diff-base main
```

This dry-run prints findings without writing any files.

#### `security-review` — full repo audit

In a Claude Code session:

```
/security-review
```

Or from a checkout:

```bash
python scripts/security-review-action.py --repo-dir . --full-repo --model sonnet
```

#### `contract-review` — deep audit for subtler bugs

For caller/callee invariant gaps — bugs where two functions each look
fine alone but break together (an auth helper named like an identity
check but matching only by name; a "verified" predicate that fails open
on null input).

In a Claude Code session:

```
/contract-review
```

Or headless from a checkout:

```bash
python scripts/contract-review.py --repo-dir . --model opus
```

Both produce the same findings table. Treat each finding as
**hypothesis-grade** — read the code and write a PoC before filing. See
[`docs/contract-review.md`](docs/contract-review.md) for hit-rate
numbers, the comparison against `security-review`, and known limitations.

---

## Does it actually work?

Short answer: yes — with caveats per mode.

### Head-to-head against bare Claude (auto-invoking skills)

We test against 134 deliberately broken fixtures — Flask login routes
with hardcoded passwords, SQL queries built from string concatenation,
file uploads without size limits. Each fixture carries a checklist of
what a thorough review should catch and fix. Claude reviews each fixture
twice — once with Soundcheck loaded, once with a generic "be a security
reviewer" prompt — and a judge model scores both against the checklist.
*Full pass* means Claude satisfies every checklist item.

Latest haiku sweep (v1.16):

| Model | With Soundcheck | Plain Claude | Lift |
|---|---|---|---|
| Haiku | **80%** full pass | 35% | +45 pts |

When the two reviews disagree, plugin-loaded reviews score higher 74 of
79 times (≥1 criterion). The mean per-fixture delta is +0.91 criteria.

Statistical detail: Wilcoxon signed-rank on per-fixture score
differences, p < 1e-4 on haiku. Methodology in
[`docs/smoke-test-methodology.md`](docs/smoke-test-methodology.md).

### External validation

Our own fixtures could bias the result toward patterns we had in mind.
Independent check on **real OWASP projects** — 13 vulnerable files pinned
from OWASP Juice Shop (TypeScript) and OWASP PyGoat (Python). Soundcheck
caught all 13 and fully fixed **12 of 13 (92%)**. The one miss —
open-redirect in Juice Shop's `redirect.ts` — Soundcheck flagged but only
partially patched.

### Review times (full-repo pipeline)

`scripts/benchmark-eval.py` against four open-source projects at pinned
commits. Times are for the `security-review` skill alone (the full
threat-model + hotspots + security-review chain is roughly 2× longer):

| Repo | Language | Haiku |
|---|---|---|
| [redash](https://github.com/getredash/redash) | Python | **~4 min** |
| [gitea](https://github.com/go-gitea/gitea) | Go | **~15 min** |
| [cal.com](https://github.com/calcom/cal.com) | TypeScript | **~1.5 min** |
| [vaultwarden](https://github.com/dani-garcia/vaultwarden) | Rust | **~11 min** |

Sonnet is 2-3× the haiku time for the same repo with denser findings.
For very large monorepos, use the PR-scoped `--diff-base` flow.

In practice:

- **Haiku handles PR gates** — typical diff-scoped reviews finish in
  1-2 minutes.
- **Sonnet handles nightly or monthly deep scans** — higher-quality
  findings, but 3-4× the per-call time.
- **Soundcheck adds no latency over bare Claude.** Across paired
  smoke-test runs, plugin-loaded reviews run slightly *faster* than bare
  — the focused skill prompt converges sooner.

### Where it's weakest

Two honest caveats:

1. **Memory safety (kernels, codecs, crypto-lib internals).** Soundcheck's
   `memory-api-misuse` and `crypto-library-misuse` skills catch local
   patterns — unchecked `malloc`, AEAD nonce reuse — but Soundcheck does
   not trace whole-program lifetimes. ASAN/UBSAN/Valgrind, fuzzers
   (libFuzzer, OSS-Fuzz), and static analyzers (`clang-tidy`, CodeQL) own
   that territory. Run them alongside Soundcheck on C/C++ codebases.
2. **`contract-review` produces hypotheses, not CVEs.** When we built
   PoCs for the findings, a meaningful share turned out to be false
   positives — the findings described real code patterns, but the
   exploit chain broke at a downstream check the audit never traced.
   Investigate each finding before filing. Numbers in
   [`docs/contract-review.md`](docs/contract-review.md).

Reproduce any of this with:
- `python scripts/smoke-test-skills.py` — paired, ~2h on haiku
- `python scripts/benchmark-realworld.py`
- `python scripts/benchmark-contract-review.py` — ~$60, ~2h

---

## Configuration

### Cost control

`security-review` and `contract-review` burn API tokens. Cap the spend
with `--max-budget-usd` to prevent runaway costs in CI:

```bash
# Cap full-repo scan at $5
python scripts/security-review-action.py --repo-dir . --full-repo \
  --model sonnet --max-budget-usd 5

# Cap contract review at $15
python scripts/contract-review.py --repo-dir . --model opus \
  --max-budget-usd 15
```

When a run hits the cap, the script exits non-zero and prints a partial
findings table. The default cap sits at **$20** for `security-review`
and **$30** for `contract-review` — always pin an explicit budget in CI
to rule out surprises.

### Optional: reinforce triggers in your `CLAUDE.md`

To apply triggers across every project (not just ones with the plugin
loaded), add this to `~/.claude/CLAUDE.md`:

```markdown
## Security

When writing code, always invoke the soundcheck plugin skills for any
code involving: authentication, authorization, cryptography, SQL/shell/
template construction, error handling, logging, deserialization, LLM
API calls, or agent workflows.
```

### Non-Anthropic providers (Bedrock, Vertex)

Soundcheck shells out to `claude -p --model <X>`, so any model string
the `claude` CLI accepts works. For Bedrock or Vertex the model alone
isn't enough — set the provider-selection env vars first:

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

Without those env vars, `claude -p --model <ARN>` hangs or fails
silently and Soundcheck surfaces a timeout. The script runs a short
preflight call before the real review to catch this fast.

---

## Trigger reference

The 52 skills auto-invoke based on patterns in their `description`
frontmatter. You do *not* have to ask Claude to run them — they fire
whenever the code Claude is about to write matches a trigger.

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
| `malloc`/`free`/`pthread_*` misuse, missing return checks, double-free, fd leak across exec | `memory-api-misuse` | CWE-690 |
| AEAD nonce reuse, ECDSA k reuse, length-extension, padding-oracle exception leakage | `crypto-library-misuse` | CWE-323 |
| SUID drop, PATH/IFS/LD_* trust, temp-file races, symlink-follow on /tmp | `privilege-handling` | CWE-271 |
| Lock held across IO/await, lock ordering, atomic memory order, double-checked locking | `concurrency-correctness` | CWE-833 |
| Untrusted integer flows into length/index/auth comparison without bounds | `numeric-trust-boundary` | CWE-190 |

### On-demand commands

| Command | What it does |
|---|---|
| `/pr-review` | Fast Critical/High gate over changed files — usually run by the [GitHub Action](https://github.com/thejefflarson/soundcheck-action), not by hand |
| `/security-review` | Full OWASP sweep — subagent pipeline with threat model, hotspot mapping, parallel auditors, design review, attack-chain analysis |
| `/contract-review` | Deep audit reading each public function alongside its callers, flagging caller/callee invariant gaps |

---

## Contributing

1. Read `CLAUDE.md` for dev conventions
2. Copy `docs/skill-template.md` to `.claude/skills/<name>/SKILL.md`
3. Fill in all fields — no TODO placeholders
4. Add a test case to `docs/test-cases/<name>.<ext>`
5. Run the static validator — must pass:
   ```bash
   python scripts/validate-skills.py --skill <name>
   ```
6. Run the smoke test to confirm Claude detects the vulnerability:
   ```bash
   python scripts/smoke-test-skills.py --skill <name> --verbose
   ```

Skills must be under 600 words, include CWE references, and have a
concrete runnable code rewrite in `Fix immediately` (or `Procedure`
for analysis/orchestrator skills). Test cases should cover multiple
languages where the vulnerable API differs. Audit status in
`docs/test-case-audit.md`.

## Nominating a new threat

The threat landscape moves faster than OWASP's publication cycle. To
nominate an emerging threat:

1. Open a GitHub Issue using the
   **[Threat Nomination](.github/ISSUE_TEMPLATE/threat-nomination.md)**
   template
2. Include at least one real-world source (CVE, writeup, or incident)
3. Paste a short code snippet showing the vulnerable pattern — if you
   can't show code, the threat may not be detectable yet

We auto-label nominations `threat-candidate` and review them quarterly.
The backlog lives in [`docs/threat-radar.md`](docs/threat-radar.md),
which tracks 14+ threats across `watching`, `candidate`, `in-progress`,
and `shipped` tiers.

---

## License

MIT
