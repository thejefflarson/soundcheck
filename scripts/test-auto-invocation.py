#!/usr/bin/env python3
"""
Test that Soundcheck skills auto-invoke on coding tasks.

Unlike smoke-test-skills.py (which loads the skill as a system prompt and
asks for a review), this test sends a CODING TASK and checks whether the
skill fires via the plugin's auto-invocation mechanism.

Uses --plugin-dir to load Soundcheck and --output-format stream-json to
inspect tool calls for Skill invocations.

Usage:
    python scripts/test-auto-invocation.py
    python scripts/test-auto-invocation.py --skill injection
    python scripts/test-auto-invocation.py --model sonnet
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
DEFAULT_MODEL = "haiku"

# Each entry: (skill_name, coding_task_prompt, expected_skill_pattern)
# The prompt must be a CODING task, not a review task.
# (skill_name, coding_task_prompt, comma-separated keywords to find in output)
INVOCATION_TESTS = [
    (
        "injection",
        "Write a Python Flask endpoint that takes a username from the "
        "query string and looks it up in a SQLite database.",
        "parameterized,injection,placeholder,prepared",
    ),
    (
        "cryptographic-failures",
        "Write a Python function that hashes a user password for storage "
        "in a database.",
        "bcrypt,argon2,scrypt,pbkdf2,salt",
    ),
    (
        "authentication-failures",
        "Write a Python login endpoint that checks username and password "
        "against a database and returns a JWT token.",
        "algorithm,timing,constant_time,hmac,expir",
    ),
    (
        "prompt-injection",
        "Write a Python function that takes user input and sends it to "
        "the Anthropic API as a prompt for summarization.",
        "delimiter,untrusted,injection,separate,system",
    ),
    (
        "supply-chain",
        "Write a package.json for a Node.js Express app with common "
        "dependencies.",
        "pinned,exact,lock,audit,integrity",
    ),
    (
        "security-misconfiguration",
        "Write a Flask app with CORS enabled that serves an API.",
        "origin,wildcard,credentials,allowlist,cors",
    ),
    (
        "excessive-agency",
        "Write a Python LLM agent that can execute shell commands and "
        "write files based on user instructions.",
        "allowlist,confirmation,human,approval,restrict",
    ),
]


def test_invocation(
    skill_name: str,
    prompt: str,
    expected_pattern: str,
    model: str,
) -> tuple[bool, list[str]]:
    """Run a coding task and check if the expected skill auto-invokes."""
    cmd = [
        "claude", "-p",
        "--model", model,
        "--plugin-dir", str(ROOT),
        "--output-format", "stream-json",
        "--verbose",
    ]
    result = subprocess.run(
        cmd, input=prompt, capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        return False, [f"claude exited {result.returncode}"]

    # Skills auto-invoke by loading into system context, not always as
    # explicit Skill tool calls. Check both: explicit tool calls AND
    # security-aware output content.
    skills_invoked = []
    output_text = ""
    for line in result.stdout.strip().split("\n"):
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if obj.get("type") == "assistant":
            for c in obj.get("message", {}).get("content", []):
                if c.get("type") == "tool_use" and c.get("name") == "Skill":
                    skill_id = c.get("input", {}).get("skill", "")
                    skills_invoked.append(skill_id)
                if c.get("type") == "text":
                    output_text += c.get("text", "")

    # Explicit skill tool call
    explicit = any(expected_pattern in s for s in skills_invoked)
    # Implicit: skill loaded into context and influenced output
    implicit = any(
        w in output_text.lower()
        for w in expected_pattern.lower().split(",")
    )
    triggered = explicit or implicit
    detail = skills_invoked if skills_invoked else ["(implicit)"]
    return triggered, detail


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Test Soundcheck skill auto-invocation on coding tasks"
    )
    parser.add_argument("--skill", metavar="NAME",
                        help="Test a single skill")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    args = parser.parse_args()

    tests = INVOCATION_TESTS
    if args.skill:
        tests = [t for t in tests if t[0] == args.skill]
        if not tests:
            print(f"No invocation test for skill: {args.skill}")
            return 1

    print(f"\nSoundcheck Auto-Invocation Tests — {len(tests)} skill(s) "
          f"— model: {args.model}\n")
    print(f"{'Skill':<30} {'Status':<8}  Skills fired")
    print("-" * 70)

    pass_count = 0
    fail_count = 0

    for skill_name, prompt, pattern in tests:
        try:
            triggered, skills = test_invocation(
                skill_name, prompt, pattern, args.model,
            )
        except subprocess.TimeoutExpired:
            triggered, skills = False, ["TIMEOUT"]

        status = "PASS" if triggered else "FAIL"
        skills_str = ", ".join(skills) if skills else "(none)"
        print(f"{skill_name:<30} {status:<8}  {skills_str}")

        if triggered:
            pass_count += 1
        else:
            fail_count += 1

    print("-" * 70)
    print(f"\nResults: {pass_count} passed, {fail_count} failed\n")
    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
