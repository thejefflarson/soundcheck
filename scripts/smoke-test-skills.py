#!/usr/bin/env python3
"""
LLM-as-judge smoke tests for Soundcheck skills.

For each skill:
  1. Loads the skill's SKILL.md as system context
  2. Sends the test case to Claude for a security review
  3. Extracts the skill's ## Verification criteria
  4. Asks a judge to evaluate the response against those criteria
  5. Reports pass/fail per criterion

Shells out to `claude` CLI — no API key needed.

Usage:
    python scripts/smoke-test-skills.py
    python scripts/smoke-test-skills.py --skill injection
    python scripts/smoke-test-skills.py --verbose
    python scripts/smoke-test-skills.py --fail-fast
    python scripts/smoke-test-skills.py --model sonnet
"""

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _claude_cli import run_claude  # noqa: E402

ROOT = Path(__file__).parent.parent
DEFAULT_MODEL = "haiku"

REVIEW_PROMPT = (
    "Review this file for security issues. "
    "Identify all vulnerabilities, explain the risks, and suggest fixes."
)

JUDGE_SYSTEM = (
    "You are a precise test evaluator for a security code review system. "
    "Evaluate whether a review response satisfies each verification criterion. "
    "Be strict but fair — a criterion is only satisfied if the response clearly "
    "demonstrates the required behavior. Output only valid JSON, no prose."
)

JUDGE_PROMPT = """\
Skill under test: {skill_name}

Verification criteria (ALL must be satisfied for the test to pass):
{criteria}

Vulnerable test case:
```
{code}
```

Security review response to evaluate:
{response}

Output JSON only:
{{
  "passed": <true if ALL criteria are satisfied, false otherwise>,
  "criteria": [
    {{
      "criterion": "<criterion text>",
      "passed": <true|false>,
      "evidence": "<brief quote or explanation>"
    }}
  ]
}}"""


def claude_call(
    user_prompt: str,
    system_prompt: str,
    model: str = DEFAULT_MODEL,
    timeout: int = 300,
    max_retries: int = 3,
) -> str:
    for attempt in range(max_retries):
        try:
            return run_claude(
                user_prompt,
                system_prompt,
                model=model,
                disable_tools=True,
                timeout=timeout,
            )
        except (RuntimeError, subprocess.TimeoutExpired):
            if attempt < max_retries - 1:
                time.sleep(5)
                continue
            raise


def find_test_cases(skill_name: str) -> list[Path]:
    """Return every test case file for a skill, sorted by extension.

    A skill may have multiple language variants (e.g. injection.py,
    injection.java, injection.go). Each is smoke-tested independently so
    language-specific API patterns actually get exercised.
    """
    test_dir = ROOT / "docs" / "test-cases"
    return sorted(test_dir.glob(f"{skill_name}.*"))


def find_all_skills() -> list[str]:
    skills_dir = ROOT / ".claude" / "skills"
    return sorted(p.name for p in skills_dir.iterdir() if (p / "SKILL.md").exists())


def extract_test_prompt(content: str) -> str | None:
    """Return the custom prompt from YAML frontmatter, or None if absent."""
    match = re.match(r"^---\n(.*?)\n---\n", content, re.DOTALL)
    if not match:
        return None
    prompt_match = re.search(r"^prompt:\s*['\"]?(.*?)['\"]?\s*$", match.group(1), re.MULTILINE)
    return prompt_match.group(1) if prompt_match else None


def extract_verification_criteria(skill_content: str) -> list[str]:
    match = re.search(r"## Verification\n(.*?)(?=\n## |\Z)", skill_content, re.DOTALL)
    if not match:
        return []
    return re.findall(r"- \[ \] (.+)", match.group(1))


def extract_json(text: str) -> str:
    """Strip markdown code fences if present, then return the first JSON object."""
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        return fenced.group(1)
    bare = re.search(r"\{.*\}", text, re.DOTALL)
    return bare.group(0) if bare else text


def run_smoke_test(
    skill_name: str,
    test_case: Path,
    model: str,
    verbose: bool = False,
) -> tuple[bool, list[dict], str]:
    """
    Run a single LLM-as-judge smoke test on one (skill, test case) pair.

    Returns (passed, criteria_results, detail_message).
    """
    skill_path = ROOT / ".claude" / "skills" / skill_name / "SKILL.md"
    if not skill_path.exists():
        return False, [], "no SKILL.md found"

    skill_content = skill_path.read_text(encoding="utf-8")
    criteria = extract_verification_criteria(skill_content)
    if not criteria:
        return False, [], "no verification criteria in SKILL.md"

    code = test_case.read_text(encoding="utf-8")
    prompt = extract_test_prompt(code) or REVIEW_PROMPT

    # Step 1: Claude reviews the test case with the skill loaded as context
    review_text = claude_call(
        f"{prompt}\n\n```\n{code}\n```",
        skill_content,
        model=model,
    )

    if verbose:
        print(f"\n--- Review: {skill_name} ---")
        print(review_text)

    # Step 2: Judge evaluates the response against the verification criteria
    criteria_block = "\n".join(f"- {c}" for c in criteria)
    judge_text = claude_call(
        JUDGE_PROMPT.format(
            skill_name=skill_name,
            criteria=criteria_block,
            code=code,
            response=review_text,
        ),
        JUDGE_SYSTEM,
        model=model,
    )

    if verbose:
        print(f"\n--- Judge: {skill_name} ---")
        print(judge_text)

    try:
        result = json.loads(extract_json(judge_text))
    except (json.JSONDecodeError, AttributeError) as exc:
        return False, [], f"judge returned invalid JSON: {exc}"

    passed = result.get("passed", False)
    criteria_results = result.get("criteria", [])

    failed = [c for c in criteria_results if not c.get("passed")]
    if passed:
        detail = f"all {len(criteria_results)} criteria passed"
    else:
        detail = f"{len(failed)}/{len(criteria_results)} criteria failed"

    return passed, criteria_results, detail


def main() -> int:
    parser = argparse.ArgumentParser(
        description="LLM-as-judge smoke tests for Soundcheck skills"
    )
    parser.add_argument("--skill", metavar="NAME", help="Test a single skill by name")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Claude model (default: {DEFAULT_MODEL})")
    parser.add_argument(
        "--verbose", action="store_true", help="Print full review and judge responses"
    )
    parser.add_argument(
        "--fail-fast", action="store_true", help="Stop on first failure"
    )
    args = parser.parse_args()

    skill_names = [args.skill] if args.skill else find_all_skills()

    # Expand each skill to one row per test-case variant.
    cases: list[tuple[str, Path]] = []
    missing: list[str] = []
    for skill_name in skill_names:
        found = find_test_cases(skill_name)
        if found:
            cases.extend((skill_name, tc) for tc in found)
        else:
            missing.append(skill_name)

    pass_count = 0
    fail_count = 0
    label_width = max(
        (len(f"{s} [{tc.suffix.lstrip('.')}]") for s, tc in cases),
        default=40,
    ) + 2

    print(f"\nSoundcheck Smoke Tests — {len(cases)} case(s) across "
          f"{len(skill_names)} skill(s) — model: {args.model}\n")
    print(f"{'Skill [lang]':<{label_width}} {'Status':<8}  Detail")
    print("-" * 80)

    for name in missing:
        print(f"{name:<{label_width}} {'SKIP':<8}  no test case found")

    # Bail out if three consecutive cases fail at the CLI boundary with
    # the same infrastructure error (e.g. expired auth, CLI not installed,
    # rate-limiting) instead of burning 90 minutes reporting the same
    # failure over and over.
    consecutive_cli_errors = 0
    aborted = False

    for i, (skill_name, test_case) in enumerate(cases):
        if i > 0:
            time.sleep(1)
        label = f"{skill_name} [{test_case.suffix.lstrip('.')}]"
        try:
            passed, criteria_results, detail = run_smoke_test(
                skill_name, test_case, model=args.model, verbose=args.verbose,
            )
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            passed, criteria_results, detail = False, [], f"error: {exc}"

        status = "PASS" if passed else "FAIL"
        print(f"{label:<{label_width}} {status:<8}  {detail}")

        if not passed and criteria_results:
            for c in criteria_results:
                if not c.get("passed"):
                    print(f"  {'':>{label_width}}         X {c['criterion']}")
                    if c.get("evidence"):
                        print(f"  {'':>{label_width}}           {c['evidence']}")

        # Track infra errors (empty-criteria failures from non-zero claude exit)
        is_cli_error = not passed and not criteria_results and detail.startswith("error:")
        if is_cli_error:
            consecutive_cli_errors += 1
        else:
            consecutive_cli_errors = 0

        if passed:
            pass_count += 1
        else:
            fail_count += 1
            if args.fail_fast:
                print("\nStopping on first failure (--fail-fast)")
                break
            if consecutive_cli_errors >= 5:
                print(
                    "\nABORT: 5 consecutive CLI errors with empty output — "
                    "likely expired auth or broken `claude` CLI. Run "
                    "`claude /login` and retry."
                )
                aborted = True
                break

    print("-" * 72)
    suffix = " (aborted)" if aborted else ""
    print(f"\nResults: {pass_count} passed, {fail_count} failed{suffix}\n")

    if aborted:
        return 2
    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
