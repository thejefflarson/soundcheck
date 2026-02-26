# Soundcheck

Automated OWASP security checks for Claude Code. 20 skills covering **OWASP Web Top 10:2025**
and **OWASP LLM Top 10:2025** that auto-invoke when Claude writes vulnerable code patterns,
rewrite the vulnerable section inline, explain the fix, and continue with your original task.

No configuration needed. No user intervention required.

---

## Install

```bash
claude plugin install https://github.com/jefftk/soundcheck
```

After installation, all 20 skills are active in every Claude Code session. Claude will
automatically invoke the relevant skill whenever it detects vulnerable code patterns.

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
| Error handlers, try/catch, API error responses, exception propagation | `exceptional-conditions` | A10:2025 |
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
2. Copy `docs/skill-template.md` to `skills/<name>/SKILL.md`
3. Fill in all fields — no TODO placeholders
4. Add a test case to `docs/test-cases/<name>.<ext>`
5. Verify the skill auto-invokes on its test case

Skills must be under 400 words, include CWE references, and have a concrete runnable
code rewrite in the "Fix immediately" section.

---

## License

MIT
