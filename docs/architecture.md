# Soundcheck Architecture

## What Soundcheck is

Soundcheck is a Claude Code plugin with 37 skills covering OWASP Web Top 10:2025,
OWASP LLM Top 10:2025, and OWASP API Security Top 10:2023. It provides three capabilities:

1. **Auto-invocation** — skills load into Claude's context when it writes code
   matching their trigger pattern, guiding it to write secure code from the start
2. **On-demand review** — `/security-review` runs a multi-stage subagent pipeline
   that produces a findings table with attack chains
3. **Automated remediation** — `/security-cleanup` applies fixes from a review,
   and `--autofix` does this in CI without human prompts

## Architecture decisions

### Detection vs remediation split

Skills detect and explain vulnerabilities but do not auto-rewrite code. This is
intentional: detection quality is 88-96% (verified against real codebases),
while rewrite quality varies by model and language. Separating the two means:

- Detection runs on haiku (cheap, fast, reliable)
- Remediation runs on whatever model the developer is using interactively
  (sonnet/opus write better code)
- The PR gate reports issues without modifying untrusted code
- `/security-cleanup` applies fixes with the developer in the loop

### Two review modes

**PR gate** (`--diff-base main`): reviews only changed files. The full pipeline
still runs for context (threat model, hotspot mapping) but findings are scoped
to the diff. Fast on haiku (~1-2m, ~$1).

**Full scan** (`--full-repo --model sonnet`): reviews the entire repository.
Sonnet finds 5x more issues than haiku at 96% precision (24/25 verified on
vaultwarden). Recommended monthly or quarterly.

### Security review pipeline

```
Stage 0 — Threat model (reads CLAUDE.md, README, structure)
Stage 1 — Hotspot map (exhaustive security-sensitive areas)
Stage 1b — Design review (missing controls via threat-model checklist)
Stage 2 — Auditors (one per chunk of ≤5 hotspots)
Stage 3 — Attack chains (sequences where A enables B)
Stage 4 — Render (findings table + chains + summary)
Stage 5 — Suggest /security-cleanup
```

Each stage runs as an isolated subagent via the Agent tool. Main context only
dispatches and merges JSON — no file reading in the main loop.

### Model behavior findings

From extensive testing (stream-json probes, A/B experiments):

- `claude -p` does NOT support parallel tool execution regardless of model.
  Haiku, sonnet, and opus all serialize Agent calls in print mode.
- Opus parallelizes in interactive sessions but not via `claude -p`.
- `--allowed-tools` does NOT reliably constrain sonnet or opus.
- Skills auto-invoke by loading into system context, not always as explicit
  Skill tool calls. The influence is visible in the output (secure code) but
  not always in the tool-call stream.
- Claude already writes secure code for common patterns (parameterized queries,
  bcrypt) even without Soundcheck. The plugin's value is in the review pipeline
  and in covering novel/domain-specific patterns (MCP, RAG, multi-agent, token
  smuggling).

### Anti-injection architecture

When scanning untrusted repos, the script uses `--append-system-prompt` to
deliver the anti-injection guard in a structurally separate system block. This
is stronger than concatenating the guard into the skill text because a crafted
file in the scanned repo cannot splice itself into the same text stream.

For `--autofix`, findings are written to a temp file and the cleanup agent
reads them via the Read tool — structurally separating untrusted LLM-generated
text from the instruction stream.

## Testing

### Smoke tests (89 fixtures)

`scripts/smoke-test-skills.py` — sends each test case to Claude with the skill
as system context, then judges the response against the skill's verification
criteria. 89 fixtures across 30 skills in Python, Java, Go, Rust, Kotlin, XML,
TOML, and Markdown.

Skills are detection-only, so criteria check whether the vulnerability was
identified and correctly categorized — not whether the rewrite compiles.

### Benchmark (4 repos × 3 skills)

`scripts/benchmark-eval.py` — runs hotspots, threat-model, and security-review
against redash (Python), gitea (Go), calcom (TypeScript), and vaultwarden
(Rust). Judge is sonnet with tool access to the actual repo for verification.

Key metrics:
- **Clarity** (1-5): is the output actionable?
- **Finding validity**: judge reads each cited file:line and confirms the claim
- **Hotspot coverage**: what fraction of the hotspot map was addressed?
- **Early exit**: did the review touch ≥3 directories?

### Auto-invocation tests

`scripts/test-auto-invocation.py` — sends coding tasks (not review tasks) to
Claude via `--plugin-dir` and checks whether the output demonstrates
security-aware behavior (parameterized queries, bcrypt, etc.).

### Self-review CI gate

`.github/workflows/self-review.yml` — runs Soundcheck against itself on every
PR. If it finds Critical/High findings in its own code, the PR can't merge.
This is how we caught a GitHub Actions expression injection that we introduced
during a cleanup fix.

## File layout

```
.claude/skills/            31 SKILL.md files (auto-load in Claude Code)
.claude-plugin/plugin.json Plugin manifest
docs/test-cases/           89 test fixtures (multi-language)
scripts/
  _claude_cli.py           Shared wrapper for claude -p
  security-review-action.py  PR gate + full scan + --autofix
  smoke-test-skills.py     Detection quality tests (LLM-as-judge)
  benchmark-eval.py        Repo-level evaluation (4 repos × 3 skills)
  test-auto-invocation.py  Auto-invocation A/B tests
  validate-skills.py       Static checks (word count, sections, CWE refs)
.github/workflows/
  self-review.yml          Soundcheck-on-Soundcheck CI gate
  skill-smoke-tests.yml    Weekly smoke tests + quarterly threat radar
  static-checks.yml        Skill file validation on push
  dependabot-automerge.yml Dependency updates (patch/minor only)
```
