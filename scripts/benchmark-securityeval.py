#!/usr/bin/env python3
"""
SecurityEval benchmark for Soundcheck skills.

Downloads the SecurityEval dataset (121 Python samples across 69 CWEs) and tests
each Soundcheck skill against every SecurityEval sample matching its CWE(s).

For each sample:
  1. Loads the matching skill's SKILL.md as system context
  2. Sends the insecure code to Claude for review
  3. Asks a judge to evaluate: was the vulnerability detected? was a fix provided?
  4. Aggregates detection and fix rates per skill

Shells out to `claude` CLI — no API key needed.

Usage:
    python scripts/benchmark-securityeval.py
    python scripts/benchmark-securityeval.py --skill injection
    python scripts/benchmark-securityeval.py --verbose
    python scripts/benchmark-securityeval.py --limit 10
    python scripts/benchmark-securityeval.py --model sonnet
"""

import argparse
import json
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _claude_cli import run_claude  # noqa: E402

ROOT = Path(__file__).parent.parent
DEFAULT_MODEL = "haiku"
DATASET_URL = (
    "https://raw.githubusercontent.com/s2e-lab/SecurityEval/master/dataset.jsonl"
)
CACHE_PATH = ROOT / ".securityeval-cache" / "dataset.jsonl"

# Overridden by --skills-dir; resolved in main() and threaded through via this global.
SKILLS_DIR: Path = ROOT / ".claude" / "skills"

# Maps SecurityEval CWE IDs to Soundcheck skill names.
CWE_TO_SKILL: dict[str, str] = {
    # injection — SQL, shell, code execution, template, XPath
    "CWE-074": "injection",
    "CWE-077": "injection",
    "CWE-078": "injection",
    "CWE-079": "injection",
    "CWE-089": "injection",
    "CWE-090": "injection",
    "CWE-091": "injection",
    "CWE-094": "injection",
    "CWE-095": "injection",
    "CWE-116": "injection",
    "CWE-099": "injection",
    "CWE-113": "injection",
    "CWE-611": "injection",
    "CWE-643": "injection",
    "CWE-776": "injection",
    "CWE-827": "injection",
    "CWE-917": "injection",
    "CWE-943": "injection",
    "CWE-1336": "injection",
    # broken-access-control — path traversal, SSRF, open redirect
    "CWE-022": "broken-access-control",
    "CWE-023": "broken-access-control",
    "CWE-036": "broken-access-control",
    "CWE-059": "broken-access-control",
    "CWE-284": "broken-access-control",
    "CWE-285": "broken-access-control",
    "CWE-250": "broken-access-control",
    "CWE-269": "broken-access-control",
    "CWE-425": "broken-access-control",
    "CWE-434": "broken-access-control",
    "CWE-601": "broken-access-control",
    "CWE-918": "broken-access-control",
    # cryptographic-failures — weak algos, RNG, cert validation
    "CWE-295": "cryptographic-failures",
    "CWE-321": "cryptographic-failures",
    "CWE-326": "cryptographic-failures",
    "CWE-327": "cryptographic-failures",
    "CWE-328": "cryptographic-failures",
    "CWE-329": "cryptographic-failures",
    "CWE-330": "cryptographic-failures",
    "CWE-331": "cryptographic-failures",
    "CWE-338": "cryptographic-failures",
    "CWE-339": "cryptographic-failures",
    "CWE-759": "cryptographic-failures",
    "CWE-760": "cryptographic-failures",
    "CWE-916": "cryptographic-failures",
    "CWE-1204": "cryptographic-failures",
    # authentication-failures — JWT, brute force, hardcoded creds
    "CWE-259": "authentication-failures",
    "CWE-287": "authentication-failures",
    "CWE-307": "authentication-failures",
    "CWE-347": "authentication-failures",
    "CWE-522": "authentication-failures",
    "CWE-306": "authentication-failures",
    "CWE-521": "authentication-failures",
    "CWE-620": "authentication-failures",
    "CWE-640": "authentication-failures",
    # security-misconfiguration — permissions, cleartext, cookies
    "CWE-276": "security-misconfiguration",
    "CWE-311": "security-misconfiguration",
    "CWE-319": "security-misconfiguration",
    "CWE-614": "security-misconfiguration",
    "CWE-732": "security-misconfiguration",
    "CWE-798": "security-misconfiguration",
    "CWE-1004": "security-misconfiguration",
    # integrity-failures — deserialization, mass assignment
    "CWE-502": "integrity-failures",
    "CWE-565": "integrity-failures",
    "CWE-915": "integrity-failures",
    # logging-failures — log injection, missing logging
    "CWE-117": "logging-failures",
    "CWE-778": "logging-failures",
    # exceptional-conditions — error message exposure, fail-open
    "CWE-200": "exceptional-conditions",
    "CWE-209": "exceptional-conditions",
    "CWE-390": "exceptional-conditions",
    "CWE-703": "exceptional-conditions",
    "CWE-755": "exceptional-conditions",
    # insecure-design — resource exhaustion, allocation without limits
    "CWE-400": "insecure-design",
    "CWE-730": "insecure-design",
    "CWE-770": "insecure-design",
    # supply-chain — inclusion from untrusted sources
    "CWE-829": "supply-chain",
    # insecure-output-handling — XSS (client-side rendering)
    "CWE-080": "insecure-output-handling",
    # sensitive-disclosure — cleartext storage, sensitive info in debug output
    "CWE-312": "sensitive-disclosure",
    "CWE-313": "sensitive-disclosure",
    "CWE-215": "sensitive-disclosure",
    # broken-access-control — path traversal, unverified ownership, filename restriction
    "CWE-283": "broken-access-control",
    "CWE-641": "broken-access-control",
    # authentication-failures — timing side channels, trusted vars from external input
    "CWE-385": "authentication-failures",
    "CWE-454": "authentication-failures",
    # exceptional-conditions — unchecked return values
    "CWE-252": "exceptional-conditions",
    # security-misconfiguration — wrong/undefined communication destination
    "CWE-941": "security-misconfiguration",
    # insecure-design — improper enforcement of behavioral workflow
    "CWE-841": "insecure-design",
}

REVIEW_PROMPT = (
    "Review this code for security issues. "
    "Identify all vulnerabilities and rewrite any insecure code."
)

# Bare arm: generic security-reviewer context, no skill content. Same shape
# as smoke-test-skills.py for consistency.
BARE_SYSTEM = (
    "You are a security code reviewer. For the submitted file: identify "
    "every vulnerability you can see, explain the risk in plain language, "
    "and show a secure rewrite. Cover authentication, authorization, "
    "injection, cryptography, error handling, logging, and any other "
    "security concerns the code presents."
)

JUDGE_SYSTEM = (
    "You are a precise test evaluator for a security code review system. "
    "Evaluate whether a review response satisfies each criterion. "
    "Be strict but fair. Output only valid JSON, no prose."
)

JUDGE_PROMPT = """\
A security reviewer examined code that contains a known {cwe} vulnerability.

Evaluate whether the review response satisfies all three criteria:

1. DETECTION: The response identifies a security vulnerability in this code.
2. CATEGORIZATION: The response correctly identifies at least one real vulnerability \
type present in the code (e.g., SQL injection, weak crypto, missing authentication). \
It does not need to cite the exact CWE number or match the labeled vulnerability — \
correctly describing any genuine vulnerability class in the code is sufficient.
3. FIX: The response proposes a concrete secure fix. This includes: a full function \
rewrite, a corrected code snippet, or a specific one-line change showing the correct \
API call or pattern. Generic advice without code ("use HTTPS", "sanitize inputs", \
"use parameterized queries") does NOT count. Showing the actual corrected call \
(e.g. `set_cookie(..., secure=True)` or `tree.xpath("...", val=value)`) DOES count.

Vulnerable code:
```python
{code}
```

Security review response to evaluate:
{response}

Output JSON only:
{{
  "passed": <true if ALL three criteria are satisfied>,
  "criteria": [
    {{"criterion": "DETECTION", "passed": <true|false>, "evidence": "<brief quote>"}},
    {{"criterion": "CATEGORIZATION", "passed": <true|false>, "evidence": "<brief quote>"}},
    {{"criterion": "FIX", "passed": <true|false>, "evidence": "<brief quote>"}}
  ]
}}"""


# ---------------------------------------------------------------------------
# Claude CLI
# ---------------------------------------------------------------------------

def claude_call(
    user_prompt: str,
    system_prompt: str,
    model: str = DEFAULT_MODEL,
    timeout: int = 300,
) -> str:
    return run_claude(
        user_prompt,
        system_prompt,
        model=model,
        disable_tools=True,
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------

def fetch_dataset(dataset_path: Path | None) -> list[dict]:
    """Load SecurityEval from a local file, cache, or GitHub."""
    if dataset_path:
        source = Path(dataset_path)
        if not source.exists():
            print(f"ERROR: dataset file not found: {source}", file=sys.stderr)
            sys.exit(1)
        print(f"Loading dataset from {source}")
    elif CACHE_PATH.exists():
        source = CACHE_PATH
        print(f"Using cached dataset: {source}")
    else:
        print(f"Downloading SecurityEval dataset from GitHub...", end=" ", flush=True)
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(DATASET_URL, CACHE_PATH)
        print("done")
        source = CACHE_PATH

    samples = []
    with source.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def extract_cwe(sample_id: str) -> str:
    """Extract CWE identifier from a SecurityEval sample ID like 'CWE-089_author_1.py'."""
    return sample_id.split("_")[0].upper()


def group_by_skill(samples: list[dict]) -> dict[str, list[dict]]:
    """Group samples by the Soundcheck skill that covers their CWE."""
    groups: dict[str, list[dict]] = {}
    for sample in samples:
        cwe = extract_cwe(sample["ID"])
        skill = CWE_TO_SKILL.get(cwe)
        if skill:
            groups.setdefault(skill, []).append(sample)
    return groups


def extract_json(text: str) -> str:
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        return fenced.group(1)
    bare = re.search(r"\{.*\}", text, re.DOTALL)
    return bare.group(0) if bare else text


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------

def _judge(code: str, cwe: str, review_text: str, model: str) -> dict:
    t0 = time.monotonic()
    judge_text = claude_call(
        JUDGE_PROMPT.format(cwe=cwe, code=code, response=review_text),
        JUDGE_SYSTEM,
        model=model,
    )
    elapsed = time.monotonic() - t0
    try:
        result = json.loads(extract_json(judge_text))
    except (json.JSONDecodeError, AttributeError):
        return {"passed": False, "criteria": [], "judge_sec": round(elapsed, 2)}
    return {
        "passed": result.get("passed", False),
        "criteria": result.get("criteria", []),
        "judge_sec": round(elapsed, 2),
    }


def run_sample(
    skill_content: str,
    skill_name: str,
    sample: dict,
    model: str,
    verbose: bool,
    include_bare: bool = False,
) -> dict:
    """Run one SecurityEval sample through the skill and judge.

    When include_bare is set, also runs a bare arm (neutral reviewer system
    prompt, no skill content) for paired overfitting analysis.
    """
    cwe = extract_cwe(sample["ID"])
    code = sample["Insecure_code"]
    user_prompt = f"{REVIEW_PROMPT}\n\n```python\n{code}\n```"

    t0 = time.monotonic()
    plugin_review = claude_call(user_prompt, skill_content, model=model)
    plugin_review_sec = round(time.monotonic() - t0, 2)
    if verbose:
        print(f"\n  [plugin review] {sample['ID']}")
        print(f"  {plugin_review[:300]}{'...' if len(plugin_review) > 300 else ''}")
    plugin_judgment = _judge(code, cwe, plugin_review, model)

    out = {
        "id": sample["ID"],
        "cwe": cwe,
        "passed": plugin_judgment["passed"],
        "criteria": plugin_judgment["criteria"],
        "plugin_review_sec": plugin_review_sec,
        "plugin_judge_sec": plugin_judgment.get("judge_sec"),
        "skill_word_count": len(skill_content.split()),
    }

    if include_bare:
        t1 = time.monotonic()
        bare_review = claude_call(user_prompt, BARE_SYSTEM, model=model)
        bare_review_sec = round(time.monotonic() - t1, 2)
        if verbose:
            print(f"  [bare review]   {sample['ID']}")
            print(f"  {bare_review[:300]}{'...' if len(bare_review) > 300 else ''}")
        bare_judgment = _judge(code, cwe, bare_review, model)
        out["bare_passed"] = bare_judgment["passed"]
        out["bare_criteria"] = bare_judgment["criteria"]
        out["bare_review_sec"] = bare_review_sec
        out["bare_judge_sec"] = bare_judgment.get("judge_sec")

    return out


def run_skill_benchmark(
    skill_name: str,
    samples: list[dict],
    model: str,
    limit: int | None,
    verbose: bool,
    include_bare: bool = False,
) -> dict:
    """Benchmark one skill against all its SecurityEval samples."""
    skill_path = SKILLS_DIR / skill_name / "SKILL.md"
    if not skill_path.exists():
        return {"skill": skill_name, "error": "SKILL.md not found"}

    skill_content = skill_path.read_text(encoding="utf-8")

    if limit:
        samples = samples[:limit]

    results = []
    for i, sample in enumerate(samples):
        if i > 0:
            time.sleep(2)
        try:
            result = run_sample(
                skill_content, skill_name, sample, model, verbose,
                include_bare=include_bare,
            )
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            result = {
                "id": sample["ID"],
                "cwe": extract_cwe(sample["ID"]),
                "passed": False,
                "criteria": [],
                "error": str(exc)[:200],
            }
        results.append(result)

    def criterion_pass(r: dict, crit_key: str, which: str = "plugin") -> bool:
        crit_field = "criteria" if which == "plugin" else "bare_criteria"
        return any(
            c.get("criterion") == crit_key and c.get("passed")
            for c in r.get(crit_field, [])
        )

    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    detected = sum(1 for r in results if criterion_pass(r, "DETECTION"))
    fixed = sum(1 for r in results if criterion_pass(r, "FIX"))

    summary = {
        "skill": skill_name,
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "detection_rate": detected / total if total else 0,
        "fix_rate": fixed / total if total else 0,
        "results": results,
    }

    if include_bare:
        b_passed = sum(1 for r in results if r.get("bare_passed"))
        b_detected = sum(1 for r in results if criterion_pass(r, "DETECTION", "bare"))
        b_fixed = sum(1 for r in results if criterion_pass(r, "FIX", "bare"))
        summary["bare_passed"] = b_passed
        summary["bare_detection_rate"] = b_detected / total if total else 0
        summary["bare_fix_rate"] = b_fixed / total if total else 0

    return summary


def print_skill_summary(summary: dict, verbose: bool) -> None:
    skill = summary["skill"]
    if "error" in summary:
        print(f"  {skill}: ERROR — {summary['error']}")
        return

    total = summary["total"]
    passed = summary["passed"]
    det_pct = int(summary["detection_rate"] * 100)
    fix_pct = int(summary["fix_rate"] * 100)

    status = "PASS" if passed == total else ("PARTIAL" if passed > 0 else "FAIL")
    print(
        f"  {skill:<28} {status:<8} "
        f"{passed}/{total} fully passed  "
        f"detect {det_pct}%  fix {fix_pct}%"
    )

    if verbose or passed < total:
        for r in summary["results"]:
            mark = "Y" if r["passed"] else "X"
            failed_criteria = [
                c["criterion"] for c in r["criteria"] if not c.get("passed")
            ]
            suffix = f"  (failed: {', '.join(failed_criteria)})" if failed_criteria else ""
            print(f"    {mark} {r['id']}{suffix}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SecurityEval benchmark for Soundcheck skills"
    )
    parser.add_argument("--skill", metavar="NAME", help="Benchmark a single skill")
    parser.add_argument("--dataset", metavar="PATH", help="Path to local dataset.jsonl")
    parser.add_argument(
        "--limit", type=int, metavar="N", help="Max samples per skill"
    )
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Claude model (default: {DEFAULT_MODEL})")
    parser.add_argument(
        "--verbose", action="store_true", help="Print review and judge responses"
    )
    parser.add_argument(
        "--skills-dir", metavar="PATH",
        help="Directory containing skill subdirectories (default: repo .claude/skills/)"
    )
    parser.add_argument(
        "--unmapped", action="store_true", help="List SecurityEval CWEs with no skill mapping and exit"
    )
    parser.add_argument(
        "--with-bare", action="store_true",
        help="Also run each sample with a neutral reviewer (no skill content) "
        "and report a paired plugin-vs-bare comparison",
    )
    args = parser.parse_args()

    samples = fetch_dataset(Path(args.dataset) if args.dataset else None)
    print(f"Loaded {len(samples)} SecurityEval samples\n")

    if args.unmapped:
        all_cwes = {extract_cwe(s["ID"]) for s in samples}
        unmapped = sorted(all_cwes - set(CWE_TO_SKILL))
        print(f"CWEs in SecurityEval with no Soundcheck skill mapping ({len(unmapped)}):")
        for cwe in unmapped:
            count = sum(1 for s in samples if extract_cwe(s["ID"]) == cwe)
            print(f"  {cwe}  ({count} sample{'s' if count != 1 else ''})")
        return 0

    global SKILLS_DIR
    if args.skills_dir:
        SKILLS_DIR = Path(args.skills_dir).resolve()
        if not SKILLS_DIR.is_dir():
            print(f"ERROR: --skills-dir not found: {SKILLS_DIR}", file=sys.stderr)
            return 1

    groups = group_by_skill(samples)

    if args.skill:
        if args.skill not in groups:
            print(f"No SecurityEval samples map to skill '{args.skill}'")
            print(f"Mapped skills: {sorted(groups)}")
            return 1
        skill_names = [args.skill]
    else:
        skill_names = sorted(groups)

    mapped_total = sum(len(groups[s]) for s in skill_names)
    print(f"SecurityEval Benchmark — {len(skill_names)} skill(s), {mapped_total} samples — model: {args.model}")
    if args.limit:
        print(f"(capped at {args.limit} samples per skill)")
    print()

    all_summaries = []
    for i, skill_name in enumerate(skill_names):
        if i > 0:
            time.sleep(1)
        samples_for_skill = groups[skill_name]
        cwes = sorted({extract_cwe(s["ID"]) for s in samples_for_skill})
        print(f"> {skill_name}  [{', '.join(cwes)}]  {len(samples_for_skill)} sample(s)")
        summary = run_skill_benchmark(
            skill_name, samples_for_skill, args.model, args.limit,
            args.verbose, include_bare=args.with_bare,
        )
        print_skill_summary(summary, args.verbose)
        all_summaries.append(summary)
        print()

    # Aggregate report
    valid = [s for s in all_summaries if "error" not in s]
    if not valid:
        return 1

    total_samples = sum(s["total"] for s in valid)
    total_passed = sum(s["passed"] for s in valid)
    avg_detect = sum(s["detection_rate"] for s in valid) / len(valid)
    avg_fix = sum(s["fix_rate"] for s in valid) / len(valid)

    print("=" * 72)
    print(f"AGGREGATE  {total_passed}/{total_samples} fully passed")
    print(f"           plugin detection rate: {int(avg_detect * 100)}%")
    print(f"           plugin fix rate:       {int(avg_fix * 100)}%")

    if args.with_bare:
        total_bare_passed = sum(s.get("bare_passed", 0) for s in valid)
        avg_bare_detect = sum(
            s.get("bare_detection_rate", 0) for s in valid
        ) / len(valid)
        avg_bare_fix = sum(
            s.get("bare_fix_rate", 0) for s in valid
        ) / len(valid)
        print()
        print(f"           bare-arm full-pass:    {total_bare_passed}/{total_samples}")
        print(f"           bare-arm detection:    {int(avg_bare_detect * 100)}%")
        print(f"           bare-arm fix rate:     {int(avg_bare_fix * 100)}%")
        # Per-sample paired agreement across all skills
        pos = neg = zero = 0
        for s in valid:
            for r in s["results"]:
                p = 1 if r.get("passed") else 0
                b = 1 if r.get("bare_passed") else 0
                if p > b: pos += 1
                elif b > p: neg += 1
                else: zero += 1
        print(f"\n           plugin > bare: {pos}   plugin < bare: {neg}   equal: {zero}")

    # Skills with lowest detection rate
    weak = sorted(valid, key=lambda s: s["detection_rate"])[:3]
    if weak and weak[0]["detection_rate"] < 1.0:
        print("\nLowest plugin detection rates:")
        for s in weak:
            if s["detection_rate"] < 1.0:
                print(f"  {s['skill']:<28} {int(s['detection_rate'] * 100)}%")

    # Latency summary
    def _pct(xs: list[float], p: float) -> float:
        if not xs: return 0.0
        s = sorted(xs)
        return s[max(0, min(len(s)-1, int(round((len(s)-1)*p/100))))]

    all_rows = [r for s in valid for r in s["results"]]
    p_rev = [r["plugin_review_sec"] for r in all_rows if r.get("plugin_review_sec") is not None]
    if p_rev:
        print("\nLatency (seconds per call):")
        print(f"  plugin review — p50 {_pct(p_rev, 50):.1f}s  p95 {_pct(p_rev, 95):.1f}s  max {max(p_rev):.1f}s")
        if args.with_bare:
            b_rev = [r["bare_review_sec"] for r in all_rows if r.get("bare_review_sec") is not None]
            if b_rev:
                print(f"  bare review   — p50 {_pct(b_rev, 50):.1f}s  p95 {_pct(b_rev, 95):.1f}s  max {max(b_rev):.1f}s")

    print()
    return 0 if total_passed == total_samples else 1


if __name__ == "__main__":
    sys.exit(main())
