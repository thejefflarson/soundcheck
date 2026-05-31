# Skill Template

Copy this file to `.claude/skills/<kebab-name>/SKILL.md` and fill in all fields.
Delete this instruction block before shipping.

---

```markdown
---
name: <kebab-name>
description: Use when writing code that [specific trigger conditions, 2-3 sentences].
  Also invoke when [secondary trigger condition].
---

# <Title> Security Check (<OWASP Category>:<Year>)

## What this checks

[1-2 sentences: what attack surface this skill protects and what the impact of a
vulnerability here is.]

## Vulnerable patterns

[2-5 patterns described as phrases, not code. Inline code is OK to name an API or
keyword; avoid multi-line snippets, language-specific syntax, and library names that
won't transfer between stacks. The auditor reads the audited file's language and
maps these patterns into it.]

- State-changing endpoint that mutates server state without a token validated against the session
- Subprocess call with shell expansion enabled and arguments interpolated from request input
- Dynamic evaluation of any user-supplied string

## Fix immediately

[Describe the fix as language-agnostic principles, never code. State the security
property the fix must establish, then trust the auditor to translate to the file's
language. No fenced code blocks. No per-framework recipes ("use Django middleware
X") that bind the fix to one stack — say what the middleware must do instead.]

For each vulnerable call site, apply the appropriate control:

- **Property 1**: [the security invariant; e.g. "user input reaches SQL only as a bound parameter, never via string interpolation"]
- **Property 2**: [next invariant]
- Translate to the language and framework of the audited file. Use the documented safe API for that stack; do not roll your own.

## Verification

Confirm the following *properties* hold (language-agnostic):

- [ ] [Specific invariant the fix establishes]
- [ ] [Specific invariant the fix establishes]
- [ ] No user-controlled data reaches [dangerous sink] without [sanitization/validation]

## References

- CWE-XXX ([CWE name](https://cwe.mitre.org/data/definitions/XXX.html))
- [OWASP <Category>:<Year>](https://owasp.org/...)
```
