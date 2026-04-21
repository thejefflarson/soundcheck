"""Shared wrapper around `claude -p` for Soundcheck scripts.

All Soundcheck Python tools shell out to the `claude` CLI rather than
calling the Anthropic SDK directly, so they share the same auth, plugin
state, and tool access. This module centralizes the subprocess
invocation so every caller uses identical argument handling.

Safety rails enforced here (single choke point for every LLM call):

- ``SOUNDCHECK_DISABLE=1`` in the environment raises ``ClaudeCLIError``
  before any subprocess is spawned — a kill switch for incident
  response.
- ``timeout`` is clamped to ``[MIN_TIMEOUT_SEC, MAX_TIMEOUT_SEC]`` so a
  misconfigured caller can't pass a zero-timeout (instant failure) or
  effectively-infinite timeout.
- ``max_budget_usd`` no longer defaults to ``None``. Callers that do not
  want a cap must pass ``0`` explicitly; everything else is clamped to
  ``[0, MAX_BUDGET_CAP_USD]``.
"""

import os
import subprocess
from pathlib import Path

MIN_TIMEOUT_SEC = 30
MAX_TIMEOUT_SEC = 1800
MAX_BUDGET_CAP_USD = 20.0


class ClaudeCLIError(RuntimeError):
    """Raised when `claude -p` exits non-zero or the call is refused."""


def run_claude(
    user_prompt: str,
    system_prompt: str,
    *,
    model: str,
    cwd: Path | None = None,
    allowed_tools: str | None = None,
    disable_tools: bool = False,
    append_system_prompt: str | None = None,
    max_budget_usd: float = 1.0,
    timeout: int = 900,
) -> str:
    """Shell out to `claude -p` and return stdout.

    Arguments:
        user_prompt: passed on stdin.
        system_prompt: passed via --system-prompt.
        model: model alias or full id (e.g. "haiku", "sonnet").
        cwd: working directory for tool resolution. None means no tools.
        allowed_tools: comma-separated allowlist. None means default
            (e.g. "Task" to lock the main loop to dispatching only).
        disable_tools: if True, pass --tools "" to disable tools entirely.
            Mutually exclusive with allowed_tools. Used by judge-style
            calls that should not touch the filesystem.
        append_system_prompt: structurally separate system block appended
            after the skill body. Use for orchestrator-level rules that
            scanned-content prompt injection cannot override.
        max_budget_usd: per-run API spend cap. None means no cap.
        timeout: subprocess timeout in seconds.

    Raises:
        ClaudeCLIError on non-zero exit.
    """
    if disable_tools and allowed_tools:
        raise ValueError("disable_tools and allowed_tools are mutually exclusive")

    if os.environ.get("SOUNDCHECK_DISABLE") == "1":
        raise ClaudeCLIError(
            "SOUNDCHECK_DISABLE=1 kill switch is set; refusing to run claude"
        )

    timeout = max(MIN_TIMEOUT_SEC, min(int(timeout), MAX_TIMEOUT_SEC))
    if max_budget_usd is None or max_budget_usd < 0:
        max_budget_usd = 0.0
    else:
        max_budget_usd = min(float(max_budget_usd), MAX_BUDGET_CAP_USD)

    cmd = ["claude", "-p", "--model", model, "--system-prompt", system_prompt]
    if append_system_prompt is not None:
        cmd.extend(["--append-system-prompt", append_system_prompt])
    if disable_tools:
        cmd.extend(["--tools", ""])
    elif allowed_tools is not None:
        cmd.extend(["--allowed-tools", allowed_tools])
    if max_budget_usd > 0:
        cmd.extend(["--max-budget-usd", str(max_budget_usd)])

    result = subprocess.run(
        cmd,
        input=user_prompt,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=cwd,
    )
    if result.returncode != 0:
        raise ClaudeCLIError(
            f"claude exited with code {result.returncode}: "
            f"{result.stderr[:500]}"
        )
    return result.stdout.strip() if result.stdout else ""
