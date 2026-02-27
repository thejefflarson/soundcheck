# Soundcheck — Dev Conventions

## What is Soundcheck?

Soundcheck is a Claude Code plugin providing 23 auto-invoking security skills that cover
OWASP Web Top 10:2025 and OWASP LLM Top 10:2025, plus emerging threats tracked in
`docs/threat-radar.md`. When Claude detects vulnerable code
patterns, the relevant skill auto-invokes, rewrites the vulnerable code, explains the
change, and continues with the original task — no user intervention required.

Auto-invocation is driven entirely by the `description` frontmatter in each `SKILL.md`.
No CLAUDE.md trigger mapping is needed — the description field IS the trigger.

## Skill Authoring Conventions

### Structure

Copy `docs/skill-template.md` exactly. Fill in all fields. Never ship a skill with TODO
placeholders.

### Length

Each skill must stay **under 400 words**. Trim aggressively. Security advice that can't
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

### "Fix immediately" section

This section must contain a **concrete, runnable code rewrite** — not advice, not
pseudocode. If the fix requires a library, name it. If the fix requires a pattern, show
the pattern. Claude will use this section to perform the actual rewrite.

### OWASP category

Include the full category identifier (e.g., `A01:2025`, `LLM08:2025`) in the skill title
and in the References section.

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
- [ ] Under 400 words
- [ ] CWE references present and accurate
- [ ] No TODO placeholders

## File Locations

- Skills: `skills/<name>/SKILL.md`
- Template: `docs/skill-template.md`
- Test cases: `docs/test-cases/<skill-name>.<ext>`
- Plugin manifest: `.claude-plugin/plugin.json`
- Threat radar: `docs/threat-radar.md`
- Threat nomination template: `.github/ISSUE_TEMPLATE/threat-nomination.md`

## Nominating a Threat

The threat landscape moves faster than OWASP's publication cycle. To nominate a new
threat for Soundcheck coverage:

1. Open a GitHub Issue using `.github/ISSUE_TEMPLATE/threat-nomination.md`
2. Include at least one real-world source (CVE, writeup, or incident)
3. Include a code snippet showing the vulnerable pattern

Nominations are labeled `threat-candidate` and reviewed quarterly. The backlog lives in
`docs/threat-radar.md` with four status tiers: `watching`, `candidate`, `in-progress`,
and `shipped`.
