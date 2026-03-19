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

Usage:
    python scripts/benchmark-securityeval.py
    python scripts/benchmark-securityeval.py --skill injection
    python scripts/benchmark-securityeval.py --verbose
    python scripts/benchmark-securityeval.py --limit 10
    python scripts/benchmark-securityeval.py --dataset /path/to/dataset.jsonl
    python scripts/benchmark-securityeval.py --skills-dir /path/to/skills

Cost estimate: ~102 matched samples × 2 calls × ~600 tokens ≈ $0.15–0.30 per full run
               Runtime: ~7 minutes at 2s inter-call delay
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

import anthropic

ROOT = Path(__file__).parent.parent
MODEL = "claude-haiku-4-5"
DATASET_URL = (
    "https://raw.githubusercontent.com/s2e-lab/SecurityEval/master/dataset.jsonl"
)
CACHE_PATH = ROOT / ".securityeval-cache" / "dataset.jsonl"

# Overridden by --skills-dir; resolved in main() and threaded through via this global.
SKILLS_DIR: Path = ROOT / "skills"

# Maps SecurityEval CWE IDs to Soundcheck skill names.
# A CWE maps to the skill best positioned to detect and fix it.
CWE_TO_SKILL: dict[str, str] = {
    # injection — SQL, shell, code execution, template, XPath
    "CWE-020": "injection",
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
    # sensitive-disclosure — cleartext storage of sensitive info
    "CWE-312": "sensitive-disclosure",
    "CWE-313": "sensitive-disclosure",
}

REVIEW_PROMPT = (
    "Review this code for security issues. "
    "Identify all vulnerabilities and rewrite any insecure code."
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


def api_call_with_retry(
    client: anthropic.Anthropic, kwargs: dict, max_retries: int = 5
) -> anthropic.types.Message:
    for attempt in range(max_retries):
        try:
            return client.messages.create(**kwargs)
        except anthropic.APIStatusError as exc:
            if exc.status_code == 429 and attempt < max_retries - 1:
                retry_after = exc.response.headers.get("retry-after")
                wait = int(float(retry_after)) if retry_after else 30 * (2**attempt)
                print(f"  [rate limited, retrying in {wait}s]", flush=True)
                time.sleep(wait)
            elif exc.status_code == 529 and attempt < max_retries - 1:
                wait = 2**attempt
                print(f"  [overloaded, retrying in {wait}s]", flush=True)
                time.sleep(wait)
            else:
                raise


def run_sample(
    client: anthropic.Anthropic,
    skill_content: str,
    skill_name: str,
    sample: dict,
    verbose: bool,
) -> dict:
    """
    Run one SecurityEval sample through the skill and judge.

    Returns a result dict with: id, cwe, passed, criteria.
    """
    cwe = extract_cwe(sample["ID"])
    code = sample["Insecure_code"]

    review_resp = api_call_with_retry(
        client,
        dict(
            model=MODEL,
            max_tokens=2048,
            system=skill_content,
            messages=[{"role": "user", "content": f"{REVIEW_PROMPT}\n\n```python\n{code}\n```"}],
        ),
    )
    review_text = review_resp.content[0].text

    if verbose:
        print(f"\n  [review] {sample['ID']}")
        print(f"  {review_text[:300]}{'...' if len(review_text) > 300 else ''}")

    judge_resp = api_call_with_retry(
        client,
        dict(
            model=MODEL,
            max_tokens=512,
            system=JUDGE_SYSTEM,
            messages=[
                {
                    "role": "user",
                    "content": JUDGE_PROMPT.format(
                        cwe=cwe, code=code, response=review_text
                    ),
                }
            ],
        ),
    )
    judge_text = judge_resp.content[0].text

    if verbose:
        print(f"  [judge]  {judge_text}")

    try:
        result = json.loads(extract_json(judge_text))
    except (json.JSONDecodeError, AttributeError):
        result = {"passed": False, "criteria": []}

    return {
        "id": sample["ID"],
        "cwe": cwe,
        "passed": result.get("passed", False),
        "criteria": result.get("criteria", []),
    }


def run_skill_benchmark(
    client: anthropic.Anthropic,
    skill_name: str,
    samples: list[dict],
    limit: int | None,
    verbose: bool,
) -> dict:
    """
    Benchmark one skill against all its SecurityEval samples.

    Returns a summary dict with: skill, total, passed, failed, detection_rate,
    fix_rate, results.
    """
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
        result = run_sample(client, skill_content, skill_name, sample, verbose)
        results.append(result)

    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    detected = sum(
        1
        for r in results
        if any(
            c.get("criterion") == "DETECTION" and c.get("passed")
            for c in r["criteria"]
        )
    )
    fixed = sum(
        1
        for r in results
        if any(
            c.get("criterion") == "FIX" and c.get("passed")
            for c in r["criteria"]
        )
    )

    return {
        "skill": skill_name,
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "detection_rate": detected / total if total else 0,
        "fix_rate": fixed / total if total else 0,
        "results": results,
    }


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
            mark = "✓" if r["passed"] else "✗"
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
    parser.add_argument(
        "--verbose", action="store_true", help="Print review and judge responses"
    )
    parser.add_argument(
        "--skills-dir", metavar="PATH",
        help="Directory containing skill subdirectories (default: repo skills/)"
    )
    parser.add_argument(
        "--unmapped", action="store_true", help="List SecurityEval CWEs with no skill mapping and exit"
    )
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY not set", file=sys.stderr)
        return 1

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

    client = anthropic.Anthropic(api_key=api_key)

    mapped_total = sum(len(groups[s]) for s in skill_names)
    print(f"SecurityEval Benchmark — {len(skill_names)} skill(s), {mapped_total} samples — model: {MODEL}")
    if args.limit:
        print(f"(capped at {args.limit} samples per skill)")
    print()

    all_summaries = []
    for i, skill_name in enumerate(skill_names):
        if i > 0:
            time.sleep(1)
        samples_for_skill = groups[skill_name]
        cwes = sorted({extract_cwe(s["ID"]) for s in samples_for_skill})
        print(f"▶ {skill_name}  [{', '.join(cwes)}]  {len(samples_for_skill)} sample(s)")
        summary = run_skill_benchmark(
            client, skill_name, samples_for_skill, args.limit, args.verbose
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
    print(f"           avg detection rate: {int(avg_detect * 100)}%")
    print(f"           avg fix rate:       {int(avg_fix * 100)}%")

    # Skills with lowest detection rate
    weak = sorted(valid, key=lambda s: s["detection_rate"])[:3]
    if weak and weak[0]["detection_rate"] < 1.0:
        print("\nLowest detection rates:")
        for s in weak:
            if s["detection_rate"] < 1.0:
                print(f"  {s['skill']:<28} {int(s['detection_rate'] * 100)}%")
    print()

    return 0 if total_passed == total_samples else 1


if __name__ == "__main__":
    sys.exit(main())
