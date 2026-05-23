#!/usr/bin/env python3
"""
Launcher for the Soundcheck contract-review mode.

Thin wrapper around ``claude -p`` with the ``contract-review`` skill
as system prompt. All orchestration — hotspot seeding, the round
loop — lives in the skill. Output is the findings table printed to
stdout.

Usage::

    python scripts/contract-review.py --repo-dir REPO --rounds 30 --model opus
    python scripts/contract-review.py --repo-dir REPO --output report.md
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _claude_cli import (  # noqa: E402
    ANTI_INJECTION, ClaudeCLIError, preflight_claude, run_claude,
)

SCRIPT_DIR = Path(__file__).parent
PLUGIN_DIR = SCRIPT_DIR.parent
SKILL_PATH = PLUGIN_DIR / ".claude" / "skills" / "contract-review" / "SKILL.md"

DEFAULT_MODEL = "opus"
DEFAULT_ROUNDS = 30
DEFAULT_MAX_HOURS = 4.0
DEFAULT_MAX_BUDGET_USD = 20.0
DEFAULT_STAGNATION = 15
DEFAULT_TIMEOUT = 1800


def main() -> int:
    p = argparse.ArgumentParser(description="Soundcheck contract-review")
    p.add_argument("--repo-dir", default=".")
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS)
    p.add_argument("--max-hours", type=float, default=DEFAULT_MAX_HOURS)
    p.add_argument("--max-budget-usd", type=float, default=DEFAULT_MAX_BUDGET_USD)
    p.add_argument("--stagnation-limit", type=int, default=DEFAULT_STAGNATION)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--output", metavar="PATH",
                   help="Write the findings table to PATH in addition to stdout")
    args = p.parse_args()

    repo_dir = Path(args.repo_dir).resolve()
    try:
        system_prompt = SKILL_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"ERROR: skill not found at {SKILL_PATH}", file=sys.stderr)
        return 2

    try:
        preflight_claude(args.model)
    except ClaudeCLIError as exc:
        print(f"ERROR: claude preflight failed for model={args.model!r}: {exc}",
              file=sys.stderr)
        return 2

    print(f"Starting contract-review in {repo_dir} "
          f"(model={args.model}, rounds={args.rounds}, "
          f"max_hours={args.max_hours}, budget=${args.max_budget_usd})",
          file=sys.stderr)

    user_prompt = (
        f"Run a Soundcheck /contract-review on this repository. "
        f"max_rounds={args.rounds}; max_hours={args.max_hours}; "
        f"stagnation_limit={args.stagnation_limit}. Follow the skill's "
        f"Procedure exactly. Keep all state in conversation memory; "
        f"do not write files. After the loop, render the findings table "
        f"and the <soundcheck-contract-summary> trailer."
    )

    try:
        response = run_claude(
            user_prompt,
            system_prompt,
            model=args.model,
            cwd=repo_dir,
            append_system_prompt=ANTI_INJECTION,
            allowed_tools="Read,Grep,Glob,Agent",
            max_budget_usd=args.max_budget_usd,
            timeout=args.timeout,
            plugin_dir=PLUGIN_DIR,
        )
    except ClaudeCLIError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(response)
    if args.output:
        Path(args.output).write_text(response, encoding="utf-8")
        print(f"\nFindings written to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
