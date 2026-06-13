# Soundcheck — Dev Conventions

## What is Soundcheck?

Soundcheck is a Claude Code plugin providing 48 auto-invoking security skills
plus three on-demand review modes (and one cleanup orchestrator), each scoped
to a distinct use case. When
Claude detects vulnerable code patterns mid-task, the relevant per-category
skill auto-invokes, flags the issue, explains the change, and continues — no
user intervention required.

Auto-invocation is driven entirely by the `description` frontmatter in each `SKILL.md`.
No CLAUDE.md trigger mapping is needed — the description field IS the trigger.

## Three review modes

The on-demand reviews are split into three discrete modes, each with its own
skill, driver script, latency profile, and target bug class. Reach for the one
that matches the situation; don't try to make one mode do another's job.

| Mode | Skill | Driver | Latency | Model | Target |
|------|-------|--------|---------|-------|--------|
| 1 — PR gate | `pr-review` | `security-review-action.py --diff-base REF` | ≤1 min | haiku | Critical/High OWASP in changed files |
| 2 — Full scan | `security-review` | `security-review-action.py --full-repo` | ~20 min | sonnet/opus | All severities, whole repo, with subagent fan-out |
| 3 — Contract review | `contract-review` | `contract-review.py --rounds N` | ~30 min | opus | Caller/callee invariant gaps that single-pass review misses |

Mode 2 dispatches 5 subagents (`threat-modeling`, `hotspot-mapping`,
`design-review`, `vulnerability-audit`, `attack-chain-analysis`). Mode 1 is
single-pass — no subagent dispatch — and filters to Critical/High only so
the gate stays fast and quiet. Mode 3 dispatches `threat-modeling`,
`hotspot-mapping`, and one `contract-audit` per round. Output is the
findings table printed to stdout — no on-disk state. A Mythos-style
trust-anchor-confusion bug that mode 2 missed twice (Botan
`certificate_known`) is the canonical mode 3 target.

## Threat model (for /security-review against this repo)

- **Purpose:** Claude Code plugin (skills) + a PR-gate GitHub Action
  (`scripts/security-review-action.py`) + a GitHub Action-style self-test.
- **Attack surface:** `scripts/security-review-action.py` (CI with write
  perms and API access), `.github/workflows/*`, `.claude-plugin/plugin.json`,
  `.claude/skills/*/SKILL.md`. Everything under `scripts/` is maintainer code
  run locally or in CI with trusted inputs.
- **Trusted inputs:** maintainer-committed skill files, `scripts/`,
  `docs/skill-template.md`, `plugin.json`, hardcoded benchmark manifests.
- **Untrusted inputs:** third-party repo content scanned by
  `security-review-action.py`, cloned benchmark repos, GitHub issue content.
- **Out of scope** (auditors should discount these):
  - Defense-in-depth hardening on local-only dev scripts (`benchmark-*.py`,
    `smoke-test-skills.py`, `validate-skills.py`).
  - Intentionally vulnerable fixtures in `docs/test-cases/`.
  - Opt-in flags whose behavior is the feature: `--apply-rewrites` on
    `security-review-action.py` hands the agent Edit access by design so CI
    can apply fixes automatically; this is opt-in, not a default.
  - Word-count / lint / style issues in skill files.

## Skill Authoring Conventions

### Structure

Copy `docs/skill-template.md` exactly. Fill in all fields. Never ship a skill with TODO
placeholders.

### Length

Each skill must stay **under 600 words**. Trim aggressively. Security advice that can't
fit is advice that won't be read.

### Description field (auto-invocation trigger)

The `description` field in the frontmatter is what causes the skill to auto-invoke. Per
the [official Skill authoring best practices](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices),
descriptions should include **both what the skill does and when to use it**, in third
person. Format:

> *"[Third-person sentence describing what the skill detects/checks/audits]. Use when
> writing [list of concrete code patterns]."*

Write the trigger to match the **code Claude is about to write**, not attack theory.

Good:
- "Detects SQL/shell/template injection sinks. Use when writing code that constructs database queries, builds SQL strings, executes shell commands..."
- "Audits LLM API call sites for missing token caps, timeouts, and prompt-injection surfaces. Use when building LLM API calls that include user-supplied content..."

Bad:
- "Use when discussing SQL injection..." (no "what")
- "Use for security review..." (vague)
- "I can help you find SQL injection bugs..." (first person)

Descriptions should be 2–3 sentences and specific enough to avoid false positives.

### CWE references

Every skill must include at least one CWE reference in the References section. Check
[cwe.mitre.org](https://cwe.mitre.org) for accuracy.

### Action section — "Fix immediately" or "Procedure"

Fix-oriented skills use `## Fix immediately` to describe the fix as **language-agnostic
principles** — never code blocks or per-language recipes. Each principle states the
security property the fix must establish (e.g. "use parameterized queries, never string
concatenation") and trusts the model to translate to the audited file's language. No
fenced code blocks. No library names except as illustrative parentheticals. The
language-mismatch problem (e.g. recommending a Node library in a Go project) is the
failure mode this rule prevents. Skills detect and explain vulnerabilities but do not
auto-rewrite code. Use `/security-cleanup` to apply fixes interactively.

Vulnerable patterns are also described as patterns, not code: bullet phrases like
"state-changing form with no CSRF token field" beat `<form method="POST">` snippets.
Inline code is fine for naming an API or function (`eval`, `SameSite`) but avoid
literal multi-line code in either `## Vulnerable patterns` or `## Fix immediately`.

Analysis/orchestration skills (hotspots, threat-model, security-review,
security-cleanup) use `## Procedure` instead. The procedure must be concrete:
numbered or labeled steps the agent follows to generate the required output.

### OWASP category

Include the full category identifier (e.g., `A01:2025`, `LLM08:2025`) in the skill title
and in the References section.

## Review pipeline shape

The review modes share a three-stage pipeline with discrete
responsibilities. Both `security-review` and `contract-review`
orchestrate the same first two stages and differ only in the
per-hotspot review subagent they dispatch.

| Stage | Subagent | Responsibility |
|---|---|---|
| 1. Threat model | `threat-modeling` | What the code does, where it runs, what's trusted, what's untrusted. Pure context — no file decisions. |
| 2. Hotspots | `hotspot-mapping` | What files and functions are interesting given the threat model. Returns `{file, lines, name, why}`. No skill mapping, no mode flag. |
| 3. Review | `vulnerability-audit` (security-review) / `contract-audit` (contract-review) | Where there are problems. Reads the hotspot's code and the relevant skill catalog; emits findings. |

`security-review` adds two orthogonal layers around stage 3:
`design-review` (parallel, operates on the whole repo + threat
model, finds missing controls) and `attack-chain-analysis`
(post-review, composes findings into chains).

When adding a new auto-invoking skill, vulnerability-audit will
pick it up automatically by reading the skill catalog in
`.claude/skills/`. There is no separate catalog list to maintain.

## Subagents (`.claude/agents/`)

Per [Claude Code subagent best practices](https://code.claude.com/docs/en/sub-agents):

- `threat-modeling` — pure context (Stage 1).
- `hotspot-mapping` — interesting code locations (Stage 2).
- `vulnerability-audit` — per-hotspot OWASP review for `security-review` (Stage 3).
- `contract-audit` — per-hotspot caller/callee invariant review for `contract-review` (Stage 3).
- `design-review` — missing-controls audit (security-review only, parallel layer).
- `attack-chain-analysis` — chain composition (security-review only, post-review).

**Reload caveat:** subagents are loaded at Claude Code session start. Editing a
file in `.claude/agents/` requires a full session restart — `/reload-plugins`
alone does not pick up agent changes. Skill edits, by contrast, are read on
demand when the skill is invoked.

Plugin subagents silently ignore `hooks`, `mcpServers`, and `permissionMode`
frontmatter fields (Anthropic doc), so don't use them in agent files shipped
with Soundcheck.

## Testing Skills

To verify a skill works:

1. Open `docs/test-cases/<skill-name>.<ext>` in your editor
2. Ask Claude: "Review this file for security issues"
3. Confirm the skill auto-invokes (visible in tool use)
4. Confirm Claude rewrites the vulnerable section, not just flags it
5. Confirm the explanation names the correct OWASP category and CWE
6. Confirm Claude would continue with the original task after remediation

## Acceptance Criteria for New Skills

- [ ] Skill auto-invokes on its canonical vulnerable pattern
- [ ] No false negatives on the test case file
- [ ] Rewrite is actually secure (not just renamed variables)
- [ ] Under 600 words
- [ ] CWE references present and accurate
- [ ] No TODO placeholders

## File Locations

- Skills: `.claude/skills/<name>/SKILL.md`
- Template: `docs/skill-template.md`
- Test cases: `docs/test-cases/<skill-name>.<ext>`
- Plugin manifest: `.claude-plugin/plugin.json`
- Threat radar: `docs/threat-radar.md`
- Threat nomination template: `.github/ISSUE_TEMPLATE/threat-nomination.md`
- Static validator: `scripts/validate-skills.py`
- Paired smoke test: `scripts/smoke-test-skills.py` (plugin vs bare arms, Wilcoxon signed-rank on per-criterion count)
- Smoke methodology: `docs/smoke-test-methodology.md`
- Security review action script: `scripts/security-review-action.py`
- Security review GitHub Action: https://github.com/thejefflarson/soundcheck-action

## Release checklist

Use `scripts/release.py` — it automates everything below. Dry-run by default:

```bash
python scripts/release.py 1.8.0            # preview
python scripts/release.py 1.8.0 --push     # apply, with confirmation prompt
```

The script:

1. Bumps `.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json` (also
   refreshing the skill count in the marketplace description)
2. Commits, tags `vX.Y.Z`, pushes soundcheck
3. Updates `SOUNDCHECK_SHA` in `../soundcheck-action/action.yml` to the new HEAD
4. Commits, tags the next `v1.0.N`, force-moves `v1`, pushes soundcheck-action

Refuses to run unless both working trees are clean and on `main`. GitHub release
notes stay manual (`gh release create ...`) so they can be hand-written.

## Lockstep with soundcheck-action

`thejefflarson/soundcheck-action` (sibling repo, usually at `../soundcheck-action`) pins a
specific soundcheck commit SHA in `action.yml` and hardcodes the path to
`.claude/skills/security-review/SKILL.md`. Any soundcheck change that moves skill files,
renames the `security-review` skill, alters its sibling-skill discovery (the action does
`skills_dir = skill_path.parent.parent`), or changes the structured-output tags the
review script parses (`<soundcheck-rewrite>`, `<soundcheck-findings>`) requires a
matching commit + tag in soundcheck-action.

## Nominating a Threat

The threat landscape moves faster than OWASP's publication cycle. To nominate a new
threat for Soundcheck coverage:

1. Open a GitHub Issue using `.github/ISSUE_TEMPLATE/threat-nomination.md`
2. Include at least one real-world source (CVE, writeup, or incident)
3. Include a code snippet showing the vulnerable pattern

Nominations are labeled `threat-candidate` and reviewed quarterly. The backlog lives in
`docs/threat-radar.md` with four status tiers: `watching`, `candidate`, `in-progress`,
and `shipped`.
