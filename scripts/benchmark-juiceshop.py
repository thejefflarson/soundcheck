#!/usr/bin/env python3
"""Juice Shop precision/recall benchmark for /security-review.

Runs the full /security-review pipeline against OWASP Juice Shop pinned
to a specific commit, then matches the returned findings against the
canonical challenge list (data/static/challenges.yml) using a sonnet
judge. Reports precision, recall, and F1 against the source-detectable
subset of challenges (the judge decides what counts as source-visible;
challenges that require running the app to observe are excluded from
the recall denominator).

Unlike benchmark-realworld.py (per-file, per-skill), this is a
whole-repo review-mode benchmark. It measures how much of Juice Shop's
labeled bug set /security-review actually surfaces.

Usage::

    python scripts/benchmark-juiceshop.py
    python scripts/benchmark-juiceshop.py --model sonnet
    python scripts/benchmark-juiceshop.py --no-clone
    python scripts/benchmark-juiceshop.py --verbose

Caveat: Juice Shop is famous. LLMs have almost certainly seen it in
training data, so a high recall number is partly memorisation. Pair
this with a less-well-known vuln app for a cleaner signal.
"""

from __future__ import annotations

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
CACHE_DIR = ROOT / ".juiceshop-benchmark"
SKILLS_DIR = ROOT / ".claude" / "skills"

JUICE_SHOP_REPO = "juice-shop/juice-shop"
# Same commit benchmark-realworld.py pins.
JUICE_SHOP_COMMIT = "8262a6a5b1686df7acbe451943b704e53b250c6b"

DEFAULT_REVIEW_MODEL = "sonnet"
JUDGE_MODEL = "sonnet"

REVIEW_PROMPT = (
    # Anchor: without this, --plugin-dir leaks the model's attention to "
    # the Soundcheck plugin repo and the review scans Soundcheck itself.
    "The target codebase is the current working directory — OWASP Juice "
    "Shop. Only analyze files in the current working directory. Do NOT "
    "analyze files from any parent directory, from --plugin-dir, or from "
    "any absolute path outside this working directory. If a subagent "
    "returns findings that cite files not present under this cwd, "
    "discard them.\n\n"
    "Run /security-review on this repository following its skill "
    "instructions exactly — threat-modeling, hotspot-mapping, then "
    "vulnerability-audit / design-review / attack-chain-analysis. "
    "\n\n"
    "Your FINAL message must be the complete merged findings table in "
    "GitHub-flavoured markdown, one row per finding, with columns: "
    "severity, file, line, category, finding, fix. Do not truncate, do "
    "not summarise, do not describe what you did — the table itself IS "
    "the deliverable. Aim for at least 20 rows on a codebase this size."
)

JUDGE_SYSTEM = (
    "You are grading a security review against OWASP Juice Shop's "
    "canonical challenge list. You are a strict, calibrated judge. "
    "Read data/static/challenges.yml from the repo, then match the "
    "reviewer's findings against those challenges. Return JSON only."
)

JUDGE_PROMPT = """The security reviewer produced these findings against OWASP Juice Shop
(commit {commit}):

--- BEGIN REVIEWER FINDINGS ---
{findings}
--- END REVIEWER FINDINGS ---

Your task:

1. Read `data/static/challenges.yml`. Every entry is a labelled planted
   bug. For each challenge, decide whether it is SOURCE-DETECTABLE — a
   competent auditor reading the source could name the vulnerability
   without running the app or crafting a payload. Behavioural
   challenges (CAPTCHA solving, UI-only interactions, timing games)
   are NOT source-detectable and must be excluded.

2. Build the ground-truth set G = source-detectable challenges. Record
   |G|.

3. Match reviewer findings against G. A finding matches a challenge
   iff it names the same vulnerable behaviour at (roughly) the same
   file/route. Cross-check by reading the cited files. One finding may
   match at most one challenge; one challenge may match at most one
   finding.

4. Classify each finding as one of:
   - TP: matches a challenge in G
   - FP: does not match any challenge in G (either a hallucination or
     a real bug not on the challenge list — count both as FP for this
     metric; note "off-list-real" ones separately)
   - OFF_SCOPE: matches a challenge that is NOT source-detectable
     (exclude from both TP and FP)

5. Classify each unmatched challenge in G as FN.

Return ONLY this JSON, no prose:

```json
{{
  "ground_truth_total": <int, |G|>,
  "excluded_behavioural": <int, challenges excluded because not source-detectable>,
  "tp": <int>,
  "fp": <int>,
  "off_list_real": <int, subset of fp that seem to be real bugs>,
  "off_scope": <int>,
  "fn": <int>,
  "unmatched_challenges": [<challenge key strings, up to 20>],
  "unmatched_findings": [<one-line summary of each FP, up to 20>],
  "notes": "<one paragraph on judgment calls and confidence>"
}}
```
"""

_JUDGE_REQUIRED = {
    "ground_truth_total": int,
    "tp": int,
    "fp": int,
    "fn": int,
}


def fmt_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    return f"{seconds / 60:.1f}m"


def clone_juice_shop() -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    repo_dir = CACHE_DIR / "juice-shop"
    if (repo_dir / ".git").exists():
        sha = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
            capture_output=True, text=True,
        ).stdout.strip()
        if sha == JUICE_SHOP_COMMIT:
            print(f"  Cached clone at {repo_dir} (HEAD={sha[:12]})")
            return repo_dir
        print(f"  Cached clone is at {sha[:12]}, resetting to pin...")
        subprocess.run(
            ["git", "-C", str(repo_dir), "fetch", "--depth", "1",
             "origin", JUICE_SHOP_COMMIT], check=True,
        )
        subprocess.run(
            ["git", "-C", str(repo_dir), "checkout", JUICE_SHOP_COMMIT],
            check=True,
        )
        return repo_dir

    print(f"  Cloning {JUICE_SHOP_REPO} @ {JUICE_SHOP_COMMIT[:12]}...",
          end=" ", flush=True)
    subprocess.run(
        ["git", "clone", "-q", f"https://github.com/{JUICE_SHOP_REPO}.git",
         str(repo_dir)], check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo_dir), "checkout", "-q", JUICE_SHOP_COMMIT],
        check=True,
    )
    print("done")
    return repo_dir


def run_review(repo_dir: Path, model: str) -> tuple[str, float]:
    skill = (SKILLS_DIR / "security-review" / "SKILL.md").read_text()
    print(f"  Running /security-review ({model}) — expect ~30min...",
          flush=True)
    start = time.perf_counter()
    response = run_claude(
        REVIEW_PROMPT,
        skill,
        model=model,
        cwd=repo_dir,
        allowed_tools="Agent",
        plugin_dir=ROOT,
        timeout=1800,
        max_budget_usd=35.0,
    )
    elapsed = time.perf_counter() - start
    print(f"  Review done ({fmt_duration(elapsed)}, "
          f"{len(response)} chars)")
    return response, elapsed


def run_judge(repo_dir: Path, findings: str) -> dict:
    # Cap findings to keep the judge prompt bounded. 60k chars is well
    # above any realistic review-mode output but stops runaway text
    # from blowing the judge context.
    findings = findings[:60_000].replace("{", "{{").replace("}", "}}")
    prompt = JUDGE_PROMPT.format(commit=JUICE_SHOP_COMMIT[:12],
                                 findings=findings)
    print(f"  Running judge ({JUDGE_MODEL})...", flush=True)
    start = time.perf_counter()
    text = run_claude(
        prompt,
        JUDGE_SYSTEM,
        model=JUDGE_MODEL,
        cwd=repo_dir,
        timeout=1800,
        max_budget_usd=5.0,
    )
    elapsed = time.perf_counter() - start
    print(f"  Judge done ({fmt_duration(elapsed)})")

    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        raw = fenced.group(1)
    else:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if not m:
            return {"error": "judge returned no JSON", "raw": text[:500]}
        raw = m.group(0)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {"error": f"judge JSON parse failed: {exc}",
                "raw": raw[:500]}
    for field, typ in _JUDGE_REQUIRED.items():
        if not isinstance(data.get(field), typ):
            return {"error": f"judge JSON missing/wrong-type: {field}",
                    "raw": raw[:500]}
    return data


def print_report(judge: dict, review_seconds: float) -> None:
    if "error" in judge:
        print(f"\nJUDGE ERROR: {judge['error']}")
        print(f"Raw: {judge.get('raw', '')[:400]}")
        return

    tp = judge["tp"]
    fp = judge["fp"]
    fn = judge["fn"]
    off_scope = judge.get("off_scope", 0)
    gt = judge["ground_truth_total"]
    off_list_real = judge.get("off_list_real", 0)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)

    print("\n" + "=" * 60)
    print("Juice Shop /security-review — precision/recall")
    print("=" * 60)
    print(f"Commit:                {JUICE_SHOP_COMMIT[:12]}")
    print(f"Review wall time:      {fmt_duration(review_seconds)}")
    print(f"Ground-truth (G):      {gt} source-detectable challenges")
    print(f"Excluded behavioural:  {judge.get('excluded_behavioural', 0)}")
    print()
    print(f"TP:                    {tp}")
    print(f"FP:                    {fp}  (of which off-list real bugs: "
          f"{off_list_real})")
    print(f"FN:                    {fn}")
    print(f"Off-scope matches:     {off_scope}")
    print()
    print(f"Precision:             {precision:.2%}")
    print(f"Recall:                {recall:.2%}")
    print(f"F1:                    {f1:.2%}")

    unmatched_c = judge.get("unmatched_challenges", [])
    if unmatched_c:
        print(f"\nSample missed challenges (up to 20):")
        for c in unmatched_c[:20]:
            print(f"  - {c}")

    unmatched_f = judge.get("unmatched_findings", [])
    if unmatched_f:
        print(f"\nSample unmatched findings (up to 20):")
        for f in unmatched_f[:20]:
            print(f"  - {f}")

    notes = judge.get("notes")
    if notes:
        print(f"\nJudge notes:\n  {notes}")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--model", default=DEFAULT_REVIEW_MODEL,
                   help="Model for /security-review (default: sonnet)")
    p.add_argument("--no-clone", action="store_true",
                   help="Assume repo is already cloned in cache")
    p.add_argument("--verbose", action="store_true",
                   help="Print full reviewer response before judging")
    p.add_argument("--dump", type=Path,
                   help="Write raw review + judge output to this JSON file")
    p.add_argument("--reuse-review", type=Path,
                   help="Skip the review step; load findings from a "
                        "prior --dump JSON. Useful for iterating on the "
                        "judge prompt without paying for another review.")
    args = p.parse_args()

    print("Juice Shop precision/recall benchmark")
    print(f"  cache: {CACHE_DIR}")
    print(f"  pin:   {JUICE_SHOP_COMMIT[:12]}")
    print(f"  model: {args.model} (judge: {JUDGE_MODEL})")
    print()

    if args.no_clone:
        repo_dir = CACHE_DIR / "juice-shop"
        if not repo_dir.exists():
            print(f"ERROR: --no-clone but no cached clone at {repo_dir}",
                  file=sys.stderr)
            return 1
    else:
        repo_dir = clone_juice_shop()

    if args.reuse_review:
        prior = json.loads(args.reuse_review.read_text())
        findings = prior["findings"]
        review_seconds = prior.get("review_seconds", 0.0)
        print(f"  Reusing review from {args.reuse_review} "
              f"({len(findings)} chars, {fmt_duration(review_seconds)})")
    else:
        findings, review_seconds = run_review(repo_dir, args.model)
    if args.verbose:
        print("\n--- REVIEWER FINDINGS ---")
        print(findings)
        print("--- END ---\n")

    # Dump the review BEFORE the judge runs — a judge crash (rate limit,
    # timeout, bad JSON) should not force us to pay for the review again.
    if args.dump:
        args.dump.write_text(json.dumps({
            "commit": JUICE_SHOP_COMMIT,
            "review_model": args.model,
            "judge_model": JUDGE_MODEL,
            "review_seconds": review_seconds,
            "findings": findings,
            "judge": None,
        }, indent=2))
        print(f"  Wrote review to {args.dump} (judge pending)")

    if len(findings) < 2000:
        print(f"\n  WARNING: review output is only {len(findings)} chars — "
              "the orchestrator likely returned a stub instead of the "
              "full findings table. Judging anyway, but expect noise.")

    judge = run_judge(repo_dir, findings)
    print_report(judge, review_seconds)

    if args.dump:
        args.dump.write_text(json.dumps({
            "commit": JUICE_SHOP_COMMIT,
            "review_model": args.model,
            "judge_model": JUDGE_MODEL,
            "review_seconds": review_seconds,
            "findings": findings,
            "judge": judge,
        }, indent=2))
        print(f"\nWrote {args.dump}")

    return 0 if "error" not in judge else 1


if __name__ == "__main__":
    sys.exit(main())
