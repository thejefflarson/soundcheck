#!/usr/bin/env python3
"""
LLM-as-judge smoke tests for Soundcheck skills.

For each skill:
  1. Loads the skill's SKILL.md as system context
  2. Sends the test case to Claude for a security review
  3. Extracts the skill's ## Verification criteria
  4. Asks a judge to evaluate the response against those criteria
  5. Reports pass/fail per criterion

Usage:
    python scripts/smoke-test-skills.py
    python scripts/smoke-test-skills.py --skill injection
    python scripts/smoke-test-skills.py --verbose
    python scripts/smoke-test-skills.py --fail-fast

Cost estimate: ~26 skills × 2 calls × ~800 tokens ≈ $0.30–0.60 per full run
"""

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

import anthropic

ROOT = Path(__file__).parent.parent
MODEL = "claude-haiku-4-5"

REVIEW_PROMPT = (
    "Review this file for security issues. "
    "Identify all vulnerabilities and rewrite any insecure code."
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


def find_test_case(skill_name: str) -> Path | None:
    test_dir = ROOT / "docs" / "test-cases"
    matches = list(test_dir.glob(f"{skill_name}.*"))
    return matches[0] if matches else None


def find_all_skills() -> list[str]:
    skills_dir = ROOT / "skills"
    return sorted(p.name for p in skills_dir.iterdir() if (p / "SKILL.md").exists())


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


def api_call_with_retry(
    client: anthropic.Anthropic, kwargs: dict, max_retries: int = 5
) -> anthropic.types.Message:
    for attempt in range(max_retries):
        try:
            return client.messages.create(**kwargs)
        except anthropic.APIStatusError as exc:
            if exc.status_code == 529 and attempt < max_retries - 1:
                wait = 2**attempt
                print(f"  [overloaded, retrying in {wait}s]", flush=True)
                time.sleep(wait)
            else:
                raise


def run_smoke_test(
    client: anthropic.Anthropic,
    skill_name: str,
    verbose: bool = False,
) -> tuple[bool, list[dict], str]:
    """
    Run a single LLM-as-judge smoke test.

    Returns (passed, criteria_results, detail_message).
    """
    test_case = find_test_case(skill_name)
    if test_case is None:
        return False, [], "no test case found"

    skill_path = ROOT / "skills" / skill_name / "SKILL.md"
    if not skill_path.exists():
        return False, [], "no SKILL.md found"

    skill_content = skill_path.read_text(encoding="utf-8")
    criteria = extract_verification_criteria(skill_content)
    if not criteria:
        return False, [], "no verification criteria in SKILL.md"

    code = test_case.read_text(encoding="utf-8")

    # Step 1: Claude reviews the test case with the skill loaded as context
    review_resp = api_call_with_retry(
        client,
        dict(
            model=MODEL,
            max_tokens=2048,
            system=skill_content,
            messages=[
                {"role": "user", "content": f"{REVIEW_PROMPT}\n\n```\n{code}\n```"}
            ],
        ),
    )
    review_text = review_resp.content[0].text

    if verbose:
        print(f"\n--- Review: {skill_name} ---")
        print(review_text)

    # Step 2: Judge evaluates the response against the verification criteria
    criteria_block = "\n".join(f"- {c}" for c in criteria)
    judge_resp = api_call_with_retry(
        client,
        dict(
            model=MODEL,
            max_tokens=1024,
            system=JUDGE_SYSTEM,
            messages=[
                {
                    "role": "user",
                    "content": JUDGE_PROMPT.format(
                        skill_name=skill_name,
                        criteria=criteria_block,
                        code=code,
                        response=review_text,
                    ),
                }
            ],
        ),
    )
    judge_text = judge_resp.content[0].text

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
    parser.add_argument(
        "--verbose", action="store_true", help="Print full review and judge responses"
    )
    parser.add_argument(
        "--fail-fast", action="store_true", help="Stop on first failure"
    )
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY environment variable not set", file=sys.stderr)
        return 1

    client = anthropic.Anthropic(api_key=api_key)
    skill_names = [args.skill] if args.skill else find_all_skills()

    pass_count = 0
    fail_count = 0
    col_width = max(len(n) for n in skill_names) + 2

    print(f"\nSoundcheck Smoke Tests — {len(skill_names)} skill(s) — model: {MODEL}\n")
    print(f"{'Skill':<{col_width}} {'Status':<8}  Detail")
    print("-" * 72)

    for i, skill_name in enumerate(skill_names):
        if i > 0:
            time.sleep(1)
        try:
            passed, criteria_results, detail = run_smoke_test(
                client, skill_name, verbose=args.verbose
            )
        except anthropic.APIError as exc:
            passed, criteria_results, detail = False, [], f"API error: {exc}"

        status = "PASS" if passed else "FAIL"
        print(f"{skill_name:<{col_width}} {status:<8}  {detail}")

        # On failure, show which criteria didn't pass and why
        if not passed and criteria_results:
            for c in criteria_results:
                if not c.get("passed"):
                    print(f"  {'':>{col_width}}           ✗ {c['criterion']}")
                    if c.get("evidence"):
                        print(f"  {'':>{col_width}}             {c['evidence']}")

        if passed:
            pass_count += 1
        else:
            fail_count += 1
            if args.fail_fast:
                print("\nStopping on first failure (--fail-fast)")
                break

    print("-" * 72)
    print(f"\nResults: {pass_count} passed, {fail_count} failed\n")

    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
