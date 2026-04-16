"""Shared wrapper around `claude -p` for Soundcheck scripts.

All Soundcheck Python tools shell out to the `claude` CLI rather than
calling the Anthropic SDK directly, so they share the same auth, plugin
state, and tool access. This module centralizes the subprocess
invocation so every caller uses identical argument handling.
"""

import subprocess
from pathlib import Path


class ClaudeCLIError(RuntimeError):
    """Raised when `claude -p` exits non-zero."""


def run_claude(
    user_prompt: str,
    system_prompt: str,
    *,
    model: str,
    cwd: Path | None = None,
    allowed_tools: str | None = None,
    disable_tools: bool = False,
    append_system_prompt: str | None = None,
    max_budget_usd: float | None = None,
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

    cmd = ["claude", "-p", "--model", model, "--system-prompt", system_prompt]
    if append_system_prompt is not None:
        cmd.extend(["--append-system-prompt", append_system_prompt])
    if disable_tools:
        cmd.extend(["--tools", ""])
    elif allowed_tools is not None:
        cmd.extend(["--allowed-tools", allowed_tools])
    if max_budget_usd is not None:
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
