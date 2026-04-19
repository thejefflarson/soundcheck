#!/usr/bin/env python3
"""
Paired smoke test for Soundcheck skills.

For each (skill, test-case) pair:
  1. Runs TWO reviews of the same vulnerable test case — one with the
     skill's SKILL.md loaded as system context ("plugin" arm), and one
     with a neutral security-reviewer system prompt ("bare" arm).
  2. Extracts the skill's ## Verification criteria.
  3. Judges both reviews against those criteria, producing a per-criterion
     pass/fail for each arm.
  4. Compares criteria-satisfied counts pairwise and reports a Wilcoxon
     signed-rank test over the deltas.

Replaces the earlier plugin-only smoke test and the plugin-vs-bare A/B
test. The ordinal per-row score (count of criteria satisfied) carries far
more signal than binary safe/unsafe, so statistical power is much higher
at the same sample size.

Shells out to `claude` CLI. No API key needed.

Usage:
    python scripts/smoke-test-skills.py
    python scripts/smoke-test-skills.py --skill injection
    python scripts/smoke-test-skills.py --plugin-only        # skip bare arm
    python scripts/smoke-test-skills.py --model sonnet
"""

import argparse
import json
import math
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

# Bare arm: generic security-reviewer context, no skill content. Matches
# the review task shape of the plugin arm so the only independent variable
# is "does the skill body help the model meet these criteria?"
BARE_SYSTEM = (
    "You are a security code reviewer. For the submitted file: identify "
    "every vulnerability you can see, explain the risk in plain language, "
    "and show a secure rewrite. Cover authentication, authorization, "
    "injection, cryptography, error handling, logging, and any other "
    "security concerns the code presents."
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
    """Return every test case file for a skill, sorted by extension."""
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
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        return fenced.group(1)
    bare = re.search(r"\{.*\}", text, re.DOTALL)
    return bare.group(0) if bare else text


def judge_review(
    review_text: str,
    skill_name: str,
    criteria: list[str],
    code: str,
    model: str,
) -> tuple[bool, list[dict], str]:
    """Judge a review against the verification criteria."""
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
    try:
        result = json.loads(extract_json(judge_text))
    except (json.JSONDecodeError, AttributeError) as exc:
        return False, [], f"judge returned invalid JSON: {exc}"
    return (
        result.get("passed", False),
        result.get("criteria", []),
        "",
    )


def run_paired_smoke(
    skill_name: str,
    test_case: Path,
    model: str,
    include_bare: bool,
    verbose: bool = False,
) -> dict:
    """
    Run plugin review, and optionally bare review, on one test case.
    Returns a dict with per-arm verdicts and counts.
    """
    skill_path = ROOT / ".claude" / "skills" / skill_name / "SKILL.md"
    if not skill_path.exists():
        return {"error": "no SKILL.md found"}

    skill_content = skill_path.read_text(encoding="utf-8")
    criteria = extract_verification_criteria(skill_content)
    if not criteria:
        return {"error": "no verification criteria in SKILL.md"}

    code = test_case.read_text(encoding="utf-8")
    prompt = extract_test_prompt(code) or REVIEW_PROMPT
    user_prompt = f"{prompt}\n\n```\n{code}\n```"

    # Plugin arm — skill is the system prompt
    plugin_review = claude_call(user_prompt, skill_content, model=model)
    p_passed, p_crit, _ = judge_review(
        plugin_review, skill_name, criteria, code, model
    )
    if verbose:
        print(f"\n--- plugin review: {skill_name} ---\n{plugin_review}")

    out = {
        "plugin_passed": p_passed,
        "plugin_criteria": p_crit,
        "plugin_score": sum(1 for c in p_crit if c.get("passed")),
        "total_criteria": len(criteria),
    }

    if include_bare:
        bare_review = claude_call(user_prompt, BARE_SYSTEM, model=model)
        b_passed, b_crit, _ = judge_review(
            bare_review, skill_name, criteria, code, model
        )
        if verbose:
            print(f"\n--- bare review: {skill_name} ---\n{bare_review}")
        out["bare_passed"] = b_passed
        out["bare_criteria"] = b_crit
        out["bare_score"] = sum(1 for c in b_crit if c.get("passed"))

    return out


# --- paired statistics ---------------------------------------------------

def wilcoxon_signed_rank(deltas: list[int]) -> tuple[float, int, int]:
    """Two-sided Wilcoxon signed-rank test on paired differences.

    Returns (p_value, n_nonzero, W_statistic).
    Uses normal approximation with continuity correction for n >= 10,
    exact enumeration otherwise. Tied absolute differences get the
    average rank per standard procedure.
    """
    non_zero = [d for d in deltas if d != 0]
    n = len(non_zero)
    if n == 0:
        return 1.0, 0, 0

    # Rank |d| with average-rank handling for ties.
    sorted_pairs = sorted(enumerate(non_zero), key=lambda x: abs(x[1]))
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j + 1 < n and abs(sorted_pairs[j + 1][1]) == abs(sorted_pairs[i][1]):
            j += 1
        avg = (i + j) / 2.0 + 1  # 1-based average of tied ranks
        for k in range(i, j + 1):
            ranks[sorted_pairs[k][0]] = avg
        i = j + 1

    w_plus = sum(r for r, d in zip(ranks, non_zero) if d > 0)
    w_minus = sum(r for r, d in zip(ranks, non_zero) if d < 0)
    W = min(w_plus, w_minus)

    if n >= 10:
        mean = n * (n + 1) / 4.0
        var = n * (n + 1) * (2 * n + 1) / 24.0
        # Continuity correction
        z = (abs(W - mean) - 0.5) / math.sqrt(var)
        # Two-sided p from standard normal
        p = 2 * (1 - _phi(z))
        return min(1.0, max(0.0, p)), n, int(W)

    # Small-n exact: enumerate 2^n sign assignments
    from itertools import product
    total = 0
    extreme = 0
    abs_ranks = [abs(r) for r in ranks]
    observed = w_plus
    for signs in product((-1, 1), repeat=n):
        w_p = sum(r for r, s in zip(abs_ranks, signs) if s > 0)
        total += 1
        if w_p <= min(w_plus, sum(abs_ranks) - w_plus):
            extreme += 1
    p = min(1.0, 2.0 * extreme / total)
    return p, n, int(W)


def _phi(z: float) -> float:
    """Standard normal CDF."""
    return 0.5 * (1 + math.erf(z / math.sqrt(2)))


# --- main ----------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Paired smoke test for Soundcheck skills (plugin vs bare)"
    )
    parser.add_argument("--skill", metavar="NAME", help="Test a single skill by name")
    parser.add_argument(
        "--model", default=DEFAULT_MODEL,
        help=f"Claude model (default: {DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print full review and judge responses",
    )
    parser.add_argument(
        "--fail-fast", action="store_true",
        help="Stop on first plugin-arm failure",
    )
    parser.add_argument(
        "--plugin-only", action="store_true",
        help="Skip the bare arm (faster for one-off skill iteration)",
    )
    parser.add_argument(
        "--results-jsonl", metavar="PATH",
        default="/tmp/soundcheck-runs/smoke-results.jsonl",
        help="Write one JSON row per test case for post-hoc analysis",
    )
    args = parser.parse_args()

    include_bare = not args.plugin_only

    skill_names = [args.skill] if args.skill else find_all_skills()
    cases: list[tuple[str, Path]] = []
    missing: list[str] = []
    for skill_name in skill_names:
        found = find_test_cases(skill_name)
        if found:
            cases.extend((skill_name, tc) for tc in found)
        else:
            missing.append(skill_name)

    label_width = max(
        (len(f"{s} [{tc.suffix.lstrip('.')}]") for s, tc in cases),
        default=40,
    ) + 2

    arm_label = "plugin+bare" if include_bare else "plugin-only"
    print(f"\nSoundcheck Smoke — {len(cases)} case(s) across "
          f"{len(skill_names)} skill(s) — model: {args.model} — {arm_label}\n")
    header = f"{'Skill [lang]':<{label_width}} "
    if include_bare:
        header += f"{'Plugin':<8} {'Bare':<8} {'Δ':<4}  Detail"
    else:
        header += f"{'Status':<8}  Detail"
    print(header)
    print("-" * 92)

    for name in missing:
        print(f"{name:<{label_width}} SKIP     no test case found")

    results_path = Path(args.results_jsonl)
    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_file = results_path.open("w", encoding="utf-8")

    plugin_pass = 0
    bare_pass = 0
    deltas: list[int] = []
    rows_collected = 0

    consecutive_cli_errors = 0
    aborted = False

    for i, (skill_name, test_case) in enumerate(cases):
        if i > 0:
            time.sleep(1)
        label = f"{skill_name} [{test_case.suffix.lstrip('.')}]"
        try:
            row = run_paired_smoke(
                skill_name, test_case,
                model=args.model, include_bare=include_bare,
                verbose=args.verbose,
            )
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            row = {"error": f"cli: {exc}"}

        if "error" in row:
            detail = row["error"]
            p_str = "ERR"
            b_str = "ERR" if include_bare else ""
            d_str = "—" if include_bare else ""
            if detail.startswith("cli:"):
                consecutive_cli_errors += 1
        else:
            consecutive_cli_errors = 0
            total = row["total_criteria"]
            p_score = row["plugin_score"]
            p_str = f"{p_score}/{total}"
            if row["plugin_passed"]:
                plugin_pass += 1
            if include_bare:
                b_score = row["bare_score"]
                b_str = f"{b_score}/{total}"
                if row["bare_passed"]:
                    bare_pass += 1
                delta = p_score - b_score
                deltas.append(delta)
                d_str = f"{delta:+d}"
                detail = (
                    "plugin > bare" if delta > 0
                    else ("plugin < bare" if delta < 0 else "same")
                )
            else:
                b_str = ""
                d_str = ""
                detail = (
                    f"all {total} criteria passed" if row["plugin_passed"]
                    else f"{total - p_score}/{total} criteria failed"
                )
            rows_collected += 1

        if include_bare:
            print(f"{label:<{label_width}} {p_str:<8} {b_str:<8} {d_str:<4}  {detail}")
        else:
            print(f"{label:<{label_width}} {p_str:<8}  {detail}")

        # Failing-criterion breakdown (plugin arm)
        if "error" not in row and not row.get("plugin_passed"):
            for c in row.get("plugin_criteria", []):
                if not c.get("passed"):
                    print(f"  {'':>{label_width}}         X {c['criterion']}")
                    if c.get("evidence"):
                        print(f"  {'':>{label_width}}           {c['evidence']}")

        emit = {"skill": skill_name, "case": test_case.name}
        emit.update(row)
        results_file.write(json.dumps(emit) + "\n")
        results_file.flush()

        if args.fail_fast and "error" not in row and not row.get("plugin_passed"):
            print("\nStopping on first plugin-arm failure (--fail-fast)")
            break
        if consecutive_cli_errors >= 5:
            print(
                "\nABORT: 5 consecutive CLI errors — likely expired auth or "
                "broken `claude` CLI. Run `claude /login` and retry."
            )
            aborted = True
            break

    results_file.close()
    print("-" * 92)
    suffix = " (aborted)" if aborted else ""

    n = rows_collected
    if include_bare and n > 0:
        p_mean = plugin_pass / n
        b_mean = bare_pass / n
        print(f"\nPer-row full-pass rate (all criteria satisfied):")
        print(f"  Plugin: {plugin_pass}/{n} ({p_mean*100:.0f}%)")
        print(f"  Bare:   {bare_pass}/{n} ({b_mean*100:.0f}%)")

        pos = sum(1 for d in deltas if d > 0)
        neg = sum(1 for d in deltas if d < 0)
        zero = sum(1 for d in deltas if d == 0)
        mean_delta = sum(deltas) / len(deltas) if deltas else 0.0
        print(f"\nPer-row criterion-count delta (plugin − bare):")
        print(f"  rows where plugin > bare: {pos}")
        print(f"  rows where plugin < bare: {neg}")
        print(f"  rows where equal:         {zero}")
        print(f"  mean delta: {mean_delta:+.2f} criteria per row")

        p_val, n_nz, W = wilcoxon_signed_rank(deltas)
        print(f"\nWilcoxon signed-rank on non-zero deltas "
              f"(n={n_nz}, W={W}):")
        print(f"  two-sided p = {p_val:.4f}")
        if n_nz == 0:
            print("  All rows tied — test uninformative.")
        elif p_val < 0.05:
            direction = "higher" if pos > neg else "lower"
            print(f"  Reject H0 at α=0.05: plugin scores {direction} "
                  f"than bare on average.")
        else:
            print("  Fail to reject H0: paired difference not significant.")
    elif not include_bare:
        print(f"\nResults: {plugin_pass} passed, "
              f"{rows_collected - plugin_pass} failed{suffix}")

    print(f"\nPer-row results written to: {results_path}\n")

    if aborted:
        return 2
    return 0 if (include_bare or plugin_pass == rows_collected) else 1


if __name__ == "__main__":
    sys.exit(main())
