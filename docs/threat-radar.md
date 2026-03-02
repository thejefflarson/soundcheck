# Soundcheck Threat Radar

A living backlog of emerging threats tracked for potential Soundcheck coverage.

## Status tiers

| Status | Meaning |
|---|---|
| `watching` | Too early, too niche, or not code-detectable yet — awareness only |
| `candidate` | Credible, code-detectable, ready for a skill to be drafted |
| `in-progress` | Skill being written |
| `shipped` | Skill exists in `skills/` |

## How to nominate a threat

Open a GitHub Issue using the [Threat Nomination](.github/ISSUE_TEMPLATE/threat-nomination.md) template.
Issues are auto-labeled `threat-candidate` for triage at the next quarterly review.

## Radar entries

### MCP Server Security
- **Status:** `shipped` (`skills/mcp-security/`)
- **OWASP:** LLM07:2025
- **Severity:** Critical
- **Why code-detectable:** Tool handlers with unconstrained path/shell inputs; hardcoded secrets in tool definitions; missing schema constraints
- **Sources:** CVE-2025-59536, CVE-2026-21852; Trail of Bits MCP security audit (2025); 43% of sampled MCP servers had critical flaws
- **Added:** 2026-02-26

### OAuth/OIDC Implementation Flaws
- **Status:** `shipped` (`skills/oauth-implementation/`)
- **OWASP:** A07:2025
- **Severity:** High
- **Why code-detectable:** `algorithms=["none"]`, prefix-match redirect_uri, missing state parameter, hardcoded secrets
- **Sources:** CVE-2025-27587, CVE-2025-29774; PortSwigger OAuth research (2025)
- **Added:** 2026-02-26

### RAG Pipeline Security
- **Status:** `shipped` (`skills/rag-security/`)
- **OWASP:** LLM01:2025
- **Severity:** High
- **Why code-detectable:** Arbitrary URL fetch without allowlist; no content length cap; retrieved content injected without delimiters
- **Sources:** OWASP LLM Top 10:2025 LLM01; Lakera RAG security research (2025)
- **Added:** 2026-02-26

### Insecure Local Data Storage
- **Status:** `shipped` (`skills/insecure-local-storage/`)
- **OWASP:** A02:2025 / Mobile M9:2024
- **Severity:** High
- **Why code-detectable:** Credentials/tokens written to plaintext files, NSUserDefaults, SharedPreferences, or temp directories without encryption
- **Added:** 2026-03-01

### IPC Security
- **Status:** `shipped` (`skills/ipc-security/`)
- **OWASP:** A01:2025 / Mobile M4:2024
- **Severity:** High
- **Why code-detectable:** URL scheme handlers without allowlists, exported Android activities without permissions, IPC sockets bound to 0.0.0.0 without authentication
- **Added:** 2026-03-01

### On-Demand Security Review
- **Status:** `shipped` (`skills/security-review/`)
- **OWASP:** A01:2025–A10:2025 + LLM01:2025–LLM10:2025
- **Severity:** N/A (orchestrator skill)
- **Why code-detectable:** User-invocable slash command; orchestrates all Soundcheck skills in sequence and produces a severity-ranked findings report
- **Added:** 2026-03-01

### Slopsquatting / AI Hallucinated Package Names
- **Status:** `candidate`
- **OWASP:** A03:2025 (extends existing `supply-chain` skill)
- **Severity:** High
- **Why code-detectable:** LLM-suggested package names that don't exist on PyPI/npm; AI-generated `requirements.txt` or `package.json` with non-existent packages
- **Notes:** Extend `supply-chain` skill rather than creating a new one; add a check for packages not found in known registries
- **Sources:** Socket research "Slopsquatting" (2025); multiple npm typosquatting incidents involving AI-generated names
- **Added:** 2026-02-26

### Multi-Agent Trust Boundaries
- **Status:** `candidate`
- **OWASP:** LLM08:2025 (Excessive Agency)
- **Severity:** High
- **Why code-detectable:** Agent-to-agent calls without authentication; downstream agents given same permissions as orchestrator; no message signing between agents
- **Sources:** OWASP Agentic AI Top 10 (December 2025); AutoGPT and LangGraph trust boundary research
- **Added:** 2026-02-26

### Token Smuggling / Unicode Homoglyph Injection
- **Status:** `candidate`
- **OWASP:** LLM01:2025
- **Severity:** Medium
- **Why code-detectable:** User input passed to LLMs without Unicode normalization; RTL override characters in untrusted strings; invisible characters in prompt construction
- **Sources:** Embrace The Red research (2025); multiple CTF demonstrations
- **Added:** 2026-02-26

### OWASP Agentic AI Top 10 (December 2025)
- **Status:** `watching`
- **OWASP:** New publication
- **Severity:** High
- **Why watching:** Publication is new; categories overlap significantly with existing LLM Top 10 skills; need to map gaps before drafting new skills
- **Sources:** OWASP Agentic AI Top 10, December 2025 (https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- **Added:** 2026-02-26

### Claude Computer Use / Screen Control Security
- **Status:** `watching`
- **OWASP:** LLM08:2025
- **Severity:** High
- **Why watching:** API surface is evolving rapidly; patterns are not yet stable enough for a reliable trigger description; revisit in Q3 2026
- **Sources:** Anthropic Computer Use documentation; PoC attacks via screen injection (2025)
- **Added:** 2026-02-26

### Fine-Tuning Poisoning via API
- **Status:** `watching`
- **OWASP:** LLM03:2025
- **Severity:** Medium
- **Why watching:** Existing `training-data-poisoning` skill covers this partially; need to assess gap for fine-tuning-specific API patterns before splitting
- **Sources:** Anthropic fine-tuning API; shadow alignment research (2025)
- **Added:** 2026-02-26

### Indirect Prompt Injection via Document Metadata
- **Status:** `watching`
- **OWASP:** LLM01:2025
- **Severity:** Medium
- **Why watching:** Overlaps with `prompt-injection` and new `rag-security` skills; monitor whether metadata-specific patterns warrant a dedicated skill
- **Sources:** Kai Greshake indirect prompt injection research (2023–2025); PDF/EXIF injection PoCs
- **Added:** 2026-02-26

### AI-Generated Code Backdoors
- **Status:** `watching`
- **OWASP:** A03:2025 / LLM03:2025
- **Severity:** Medium
- **Why watching:** Detection requires semantic analysis beyond pattern matching; not reliably code-detectable with current skill trigger mechanism
- **Sources:** "Trojan Source" research; AI-assisted backdoor PoCs (2025)
- **Added:** 2026-02-26

### Shadow AI / Unauthorized Model Usage
- **Status:** `watching`
- **OWASP:** LLM06:2025
- **Severity:** Medium
- **Why watching:** Primarily a governance/policy problem; limited code-detectable surface (some: hardcoded unofficial model endpoints, missing data classification checks)
- **Sources:** Gartner AI governance reports (2025); enterprise AI policy incidents
- **Added:** 2026-02-26

### Model Context Poisoning via Malicious Tool Results
- **Status:** `watching`
- **OWASP:** LLM01:2025 / LLM07:2025
- **Severity:** High
- **Why watching:** Significant overlap with `mcp-security` and `prompt-injection` skills; evaluate after MCP skill ships to see if a dedicated skill adds value
- **Sources:** Wiz MCP research (2025); Anthropic tool use security guidance
- **Added:** 2026-02-26

### Prompt Extraction / System Prompt Leakage
- **Status:** `watching`
- **OWASP:** LLM06:2025
- **Severity:** Medium
- **Why watching:** Primarily a runtime attack; code-detectable surface is limited to system prompts stored in plaintext or logged — partially covered by `sensitive-disclosure`
- **Sources:** Perez & Ribeiro prompt extraction research (2022–2025); ChatGPT system prompt leaks
- **Added:** 2026-02-26

---

## Quarterly review checklist

This checklist is posted automatically as a GitHub Issue each quarter (see `.github/workflows/skill-smoke-tests.yml`):

- [ ] Promote any `watching` entries to `candidate` if patterns are now code-detectable
- [ ] Check OWASP for new draft publications
- [ ] Check NVD for new AI/LLM CVEs since last review
- [ ] Review closed `threat-candidate` issues for nomination patterns
- [ ] Verify all `shipped` skills still reflect current attack patterns
