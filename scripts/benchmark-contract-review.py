#!/usr/bin/env python3
"""
Benchmark contract-review against known publicly-disclosed contract-mismatch CVEs.

Different shape from benchmark-eval.py: each fixture is a public CVE with a
*specific known target function*, and the benchmark measures two things:

 1. **Hit rate** — did contract-review surface the known bug? We check the
    skill's <soundcheck-contract> JSON block for any finding whose `impl`
    or `caller` field references the known target file:line range.
 2. **Total findings** — broken down by severity, so a maintainer can scan
    the report to triage other contract gaps the run surfaced.

Fixtures are shallow-cloned to ``~/.cache/soundcheck-benchmark-contract/``
at the *parent SHA* of the public fix commit, so the vulnerable code is
present in the working tree. Each fixture is reused across runs (no
re-clone unless the cache is missing).

Usage::

    python scripts/benchmark-contract-review.py
    python scripts/benchmark-contract-review.py --fixture botan
    python scripts/benchmark-contract-review.py --model opus --rounds 20

Cost: ~$15-20 per fixture on opus (~30 min wall each), so a full pass is
~$60 / ~2 hours. Run pre-release or after substantive contract-review or
hotspot-mapping changes.
"""

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _claude_cli import (  # noqa: E402
    ANTI_INJECTION, SEVERITY_ORDER, ClaudeCLIError, parse_tagged_json,
    run_claude,
)

ROOT = Path(__file__).parent.parent
CACHE_DIR = Path.home() / ".cache" / "soundcheck-benchmark-contract"
SKILL_PATH = ROOT / ".claude" / "skills" / "contract-review" / "SKILL.md"

# Tighter than the launcher's defaults — each fixture has a known target,
# so wide exploration is wasted budget.
DEFAULT_MODEL = "opus"
DEFAULT_ROUNDS = 12
DEFAULT_MAX_HOURS = 1.5
DEFAULT_BUDGET_USD = 20.0
DEFAULT_TIMEOUT = 1800
DEFAULT_STAGNATION = 8


FIXTURES = [
    {
        "id": "botan",
        "repo": "https://github.com/randombit/botan.git",
        "parent_sha": "11aa82ad14f902cea8a1249f54257f4a963113a1",
        "cve": "CVE-2026-34580 / GHSA-v782-6fq4-q827",
        "target": "certificate_known — trust anchor confusion",
        "target_regex": re.compile(
            r"(certstor\.h:8[0-2]|x509path\.cpp:69[3-9]|certificate_known)",
            re.IGNORECASE,
        ),
    },
    {
        "id": "bc-java",
        "repo": "https://github.com/bcgit/bc-java.git",
        "parent_sha": "8a471e58cf7f63bbc78862e44e42494d793e2e12",
        "cve": "CVE-2026-5588",
        "target": "CompositeVerifier accepts empty signature sequence",
        "target_regex": re.compile(
            r"(JcaContentVerifierProviderBuilder|CompositeVerifier"
            r"|empty.{0,30}signature)",
            re.IGNORECASE,
        ),
    },
    {
        "id": "ghidra",
        "repo": "https://github.com/NationalSecurityAgency/ghidra.git",
        "parent_sha": "78729379e471bbb3d969409be6a8c3d24af84220",
        "cve": "Ghidra Server null-signature auth bypass (Calif.io MADBugs)",
        "target": "PKIAuthenticationModule sigBytes null check skips verify",
        "target_regex": re.compile(
            r"(PKIAuthenticationModule|sigBytes)",
            re.IGNORECASE,
        ),
    },
    {
        "id": "ffmpeg",
        "repo": "https://github.com/FFmpeg/FFmpeg.git",
        "parent_sha": "795bccdaf57772b1803914dee2f32d52776518e2",
        "cve": "FFmpeg H.264 slice_num >= 0xFFFF sentinel collision",
        "target": "h264_slice slice_num overflow vs slice_table sentinel",
        "target_regex": re.compile(
            r"(h264_slice\.c|slice_num|current_slice)",
            re.IGNORECASE,
        ),
    },
]


def ensure_fixture(fx: dict) -> Path:
    """Shallow-clone the fixture at its parent SHA if not already cached."""
    target = CACHE_DIR / fx["id"]
    if target.exists() and (target / ".git").exists():
        head = subprocess.run(
            ["git", "-C", str(target), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        if head == fx["parent_sha"]:
            return target
        print(f"  [{fx['id']}] cached SHA {head[:12]} != expected "
              f"{fx['parent_sha'][:12]}, re-checking out")
        subprocess.run(
            ["git", "-C", str(target), "checkout", fx["parent_sha"]],
            check=True,
        )
        return target

    print(f"  [{fx['id']}] cloning {fx['repo']} @ {fx['parent_sha'][:12]}")
    target.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "clone", "--depth", "1", "--no-checkout", fx["repo"], str(target)],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(target), "fetch", "--depth", "1", "origin",
         fx["parent_sha"]],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(target), "checkout", fx["parent_sha"]],
        check=True,
    )
    return target


def run_contract_review(repo_dir: Path, system_prompt: str,
                        args: argparse.Namespace) -> str:
    """Run contract-review against repo_dir and return raw stdout.

    The benchmark scores the run by parsing a <soundcheck-contract>
    JSON trailer. The skill body itself no longer emits one (it's a
    user-facing Markdown report); we ask for it explicitly here so the
    benchmark is self-contained and not dependent on a convention the
    skill once carried.
    """
    user_prompt = (
        f"Run a Soundcheck /contract-review on this repository. "
        f"max_rounds={args.rounds}; max_hours={args.max_hours}; "
        f"stagnation_limit={args.stagnation_limit}. Follow the skill's "
        f"Procedure exactly. Keep all state in conversation memory; do "
        f"not write files.\n\n"
        f"This is a benchmark run — after rendering the skill's normal "
        f"Markdown report, ALSO append these two machine-readable JSON "
        f"trailers verbatim (no code fences):\n\n"
        f"<soundcheck-contract>\n"
        f"[{{\"severity\":\"Critical|High|Medium|Low\","
        f"\"impl\":\"<file>:<line>\",\"caller\":\"<file>:<line>\","
        f"\"gap\":\"<one-sentence divergence>\","
        f"\"trigger\":\"<2-4 line attacker scenario>\","
        f"\"guards_traced\":[...],"
        f"\"hotspot_key\":\"<key>\",\"round\":N}}]\n"
        f"</soundcheck-contract>\n\n"
        f"<soundcheck-contract-summary>\n"
        f"{{\"rounds\":R,\"verified\":N,\"hotspots_probed\":M,"
        f"\"stopped\":\"max_rounds|max_hours|stagnation|exhausted\"}}\n"
        f"</soundcheck-contract-summary>\n\n"
        f"Both blocks are required, even if findings is empty (`[]`)."
    )
    return run_claude(
        user_prompt,
        system_prompt,
        model=args.model,
        cwd=repo_dir,
        append_system_prompt=ANTI_INJECTION,
        allowed_tools="Read,Grep,Glob,Agent",
        max_budget_usd=args.max_budget_usd,
        timeout=args.timeout,
        plugin_dir=ROOT,
    )


def check_hit(findings: list[dict], target_regex: re.Pattern) -> dict | None:
    """Return the first finding whose impl/caller/gap matches the target."""
    for f in findings:
        haystack = " ".join(str(f.get(k, "")) for k in ("impl", "caller", "gap"))
        if target_regex.search(haystack):
            return f
    return None


def severity_breakdown(findings: list[dict]) -> dict:
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    counts["?"] = 0
    for f in findings:
        sev = f.get("severity", "?")
        counts[sev if sev in counts else "?"] += 1
    return counts


def run_one(fx: dict, system_prompt: str, args: argparse.Namespace) -> dict:
    print(f"\n=== {fx['id']} ({fx['cve']}) ===")
    repo_dir = ensure_fixture(fx)
    started = time.monotonic()
    try:
        response = run_contract_review(repo_dir, system_prompt, args)
        error = None
    except ClaudeCLIError as exc:
        response = ""
        error = str(exc)[:300]
    elapsed = time.monotonic() - started

    findings = parse_tagged_json(response, "soundcheck-contract")
    hit = check_hit(findings, fx["target_regex"]) if findings else None
    counts = severity_breakdown(findings)

    print(f"  wall: {elapsed/60:.1f} min")
    print(f"  findings: {len(findings)} "
          f"(C={counts['Critical']} H={counts['High']} "
          f"M={counts['Medium']} L={counts['Low']})")
    print(f"  target: {fx['target']}")
    print(f"  hit:    {'✓ ' + hit.get('impl', '?') if hit else '✗ not surfaced'}")
    if error:
        print(f"  error:  {error}")

    return {
        "fixture": fx["id"],
        "cve": fx["cve"],
        "target": fx["target"],
        "wall_minutes": round(elapsed / 60, 1),
        "findings_total": len(findings),
        "severity": counts,
        "hit": bool(hit),
        "hit_finding": hit,
        "error": error,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--fixture", choices=[f["id"] for f in FIXTURES],
                   help="Run a single fixture (default: all four)")
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS)
    p.add_argument("--max-hours", type=float, default=DEFAULT_MAX_HOURS)
    p.add_argument("--max-budget-usd", type=float, default=DEFAULT_BUDGET_USD)
    p.add_argument("--stagnation-limit", type=int, default=DEFAULT_STAGNATION)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--output", metavar="PATH",
                   help="Write summary JSON to PATH")
    args = p.parse_args()

    try:
        system_prompt = SKILL_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"ERROR: contract-review skill missing at {SKILL_PATH}",
              file=sys.stderr)
        return 2

    fixtures = (
        [f for f in FIXTURES if f["id"] == args.fixture]
        if args.fixture else FIXTURES
    )

    results = [run_one(fx, system_prompt, args) for fx in fixtures]

    print("\n" + "=" * 60)
    print("Contract-review benchmark summary")
    print("=" * 60)
    hits = sum(1 for r in results if r["hit"])
    total = len(results)
    print(f"  Specific-CVE hit rate: {hits}/{total}")
    print(f"  Aggregate findings:    "
          f"{sum(r['findings_total'] for r in results)}")
    print()
    print(f"  {'fixture':10s} {'wall':>6s} {'findings':>9s}  {'hit'}")
    for r in results:
        print(f"  {r['fixture']:10s} {r['wall_minutes']:>5.1f}m "
              f"{r['findings_total']:>9d}  "
              f"{'✓' if r['hit'] else '✗'} {r['target'][:50]}")

    if args.output:
        Path(args.output).write_text(json.dumps(results, indent=2))
        print(f"\nSummary written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
