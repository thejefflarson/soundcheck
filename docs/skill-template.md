# Skill Template

Copy this file to `skills/<kebab-name>/SKILL.md` and fill in all fields.
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

[2-4 antipatterns. Use inline code snippets. Show real code, not pseudocode.]

- `query = "SELECT * FROM users WHERE id = " + user_id` — string concatenation into SQL
- `subprocess.call(user_input, shell=True)` — unsanitized shell execution
- `eval(user_provided_code)` — dynamic code evaluation from user input

## Fix immediately

When this skill invokes, rewrite the vulnerable code using the pattern below. Explain
what was wrong and what changed. Then continue with the original task.

**Secure pattern:**

\```language
# Show the actual secure implementation here.
# Must be runnable, not pseudocode.
# If a library is required, name it.
\```

**Why this works:** [1-2 sentences explaining the security property the fix establishes.]

## Verification

After rewriting, confirm:

- [ ] [Specific thing to check]
- [ ] [Specific thing to check]
- [ ] No user-controlled data reaches [dangerous sink] without [sanitization/validation]

## References

- CWE-XXX ([CWE name](https://cwe.mitre.org/data/definitions/XXX.html))
- [OWASP <Category>:<Year>](https://owasp.org/...)
```
