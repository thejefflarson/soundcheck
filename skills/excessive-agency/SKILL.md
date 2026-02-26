---
name: excessive-agency
description: Use when building autonomous LLM agents, implementing multi-step agent
  pipelines, writing code where LLM output triggers real-world actions (file writes,
  API calls, emails, database changes, code execution), or designing agentic workflows
  with tool use.
---

# Excessive Agency (OWASP LLM08:2025)

## What this checks

Prevents autonomous agents from taking irreversible or high-impact actions without
human oversight. When an LLM can directly write files, send emails, or modify databases,
a single compromised or hallucinated step can cause unrecoverable damage.

## Vulnerable patterns

- Agent calls `send_email()` or `delete_record()` immediately on LLM instruction with no confirmation
- Single LLM response authorizes an irreversible production action (deploy, drop table)
- Agent runs with write access to all resources when only read is needed for the task
- No kill switch, pause mechanism, or audit trail for agent actions

## Fix immediately

When this skill invokes, rewrite the vulnerable code using the pattern below. Explain
what was wrong and what changed. Then continue with the original task.

**Secure pattern:**

```python
from enum import Enum
from dataclasses import dataclass
from typing import Any

class Impact(Enum):
    LOW = "low"        # reversible, narrow scope
    HIGH = "high"      # irreversible or broad scope

@dataclass
class AgentAction:
    name: str
    params: dict[str, Any]
    impact: Impact

# Dry-run by default; HIGH-impact actions require explicit human approval
def execute_action(action: AgentAction, *, dry_run: bool = True) -> str:
    if dry_run:
        return f"[DRY-RUN] would execute {action.name}({action.params})"

    if action.impact == Impact.HIGH:
        approved = request_human_approval(action)   # blocks until approved/denied
        if not approved:
            return "Action denied by operator."

    audit_log(action)   # always log before execution
    return dispatch(action)

# Agent loop — plan first, confirm before act
def run_agent(task: str) -> None:
    plan = llm_plan(task)           # LLM returns list[AgentAction]
    print("Proposed actions:", plan)

    # Show full plan and confirm once for LOW-impact batch; gate each HIGH-impact step
    for action in plan:
        result = execute_action(action, dry_run=False)
        print(result)
```

**Why this works:** Dry-run mode surfaces the full action plan before anything executes.
High-impact actions block on human approval. Every executed action is audit-logged
before dispatch, giving operators a kill-switch and full traceability.

## Verification

After rewriting, confirm:

- [ ] Irreversible actions (delete, send, deploy) require explicit human approval
- [ ] Agent defaults to dry-run mode; production execution is an explicit opt-in
- [ ] Permissions are scoped to the minimum required for the current task
- [ ] Every action is written to an append-only audit log before execution

## References

- CWE-272 ([Least Privilege Violation](https://cwe.mitre.org/data/definitions/272.html))
- CWE-250 ([Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html))
- [OWASP LLM08:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm08-excessive-agency/)
