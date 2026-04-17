# Soundcheck — Dev Conventions

## What is Soundcheck?

Soundcheck is a Claude Code plugin providing 39 auto-invoking security skills and one
on-demand `/security-review` command, covering OWASP, CWE, and real-world vulnerability
patterns, plus emerging threats tracked in `docs/threat-radar.md`. When Claude detects vulnerable code
patterns, the relevant skill auto-invokes, rewrites the vulnerable code, explains the
change, and continues with the original task — no user intervention required.

Auto-invocation is driven entirely by the `description` frontmatter in each `SKILL.md`.
No CLAUDE.md trigger mapping is needed — the description field IS the trigger.

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

The `description` field in the frontmatter is what causes the skill to auto-invoke. Write
it to match the **code Claude is about to write**, not attack theory. Good triggers:

- "Use when writing code that constructs database queries..."
- "Use when building LLM API calls that include user-supplied content..."

Bad triggers:
- "Use when discussing SQL injection..."
- "Use for security review..."

Descriptions should be 2–3 sentences and specific enough to avoid false positives.

### CWE references

Every skill must include at least one CWE reference in the References section. Check
[cwe.mitre.org](https://cwe.mitre.org) for accuracy.

### Action section — "Fix immediately" or "Procedure"

Fix-oriented skills use `## Fix immediately` and must contain a **concrete secure
pattern** showing the correct approach. Skills detect and explain vulnerabilities
but do not auto-rewrite code — they flag the issue, explain the risk, and show the
secure pattern as a suggestion. Use `/security-cleanup` to apply fixes interactively.

Analysis/orchestration skills (hotspots, threat-model, security-review,
security-cleanup) use `## Procedure` instead. The procedure must be concrete:
numbered or labeled steps the agent follows to generate the required output.

### OWASP category

Include the full category identifier (e.g., `A01:2025`, `LLM08:2025`) in the skill title
and in the References section.

## Updating the Security Review Skill

`.claude/skills/security-review/SKILL.md` contains a list of every Soundcheck skill with a
short description of what it covers. **When adding a new skill, add it to the list in
the "Procedure" section of that file.** The skill will not be considered during
`/security-review` sweeps otherwise.

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
- Smoke test: `scripts/smoke-test-skills.py`
- SecurityEval benchmark: `scripts/benchmark-securityeval.py`
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
