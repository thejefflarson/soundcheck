#!/usr/bin/env python3
"""
Evaluation benchmark for holistic Soundcheck skills.

Answers four questions about the toolkit:

1. Does it find bugs by reading all the hotspots in the codebase?
2. Are those bugs correct (verified against the actual code)?
3. How long does an audit take?
4. Is the output human-readable, clear, and actionable?

For each repo, runs hotspots first to produce a dynamic ground truth of
security-sensitive areas. Then runs threat-model and security-review. Each
response is judged by a stronger model (sonnet) with repo-reading tools
enabled, so the judge can actually verify claimed findings against code.

No caching. A benchmark is a benchmark.

Usage:
    python scripts/benchmark-eval.py
    python scripts/benchmark-eval.py --repo vaultwarden
    python scripts/benchmark-eval.py --model sonnet
    python scripts/benchmark-eval.py --verbose
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _claude_cli import run_claude  # noqa: E402

ROOT = Path(__file__).parent.parent
CACHE_DIR = Path.home() / ".cache" / "soundcheck-eval"
SKILLS_DIR = ROOT / ".claude" / "skills"

DEFAULT_MODEL = "haiku"
JUDGE_MODEL = "sonnet"
SKILLS = ["hotspots", "threat-model", "security-review"]

REPO_MANIFEST = [
    {"id": "redash",      "repo": "getredash/redash",    "lang": "Python"},
    {"id": "gitea",       "repo": "go-gitea/gitea",      "lang": "Go"},
    {"id": "calcom",      "repo": "calcom/cal.com",      "lang": "TypeScript"},
    {"id": "vaultwarden", "repo": "dani-garcia/vaultwarden", "lang": "Rust"},
]

DISCOVERY_PREFIX = (
    "First run Glob to enumerate source files across the entire repository. "
    "Then read files from at least 5 different top-level directories before "
    "producing your output. Only analyze source files in the current working "
    "directory — do not analyze files from any parent directory.\n\n"
)

REVIEW_PROMPTS = {
    "hotspots": (
        DISCOVERY_PREFIX
        + "Analyze the {repo_id} repository ({lang}) for security hotspots. "
        "Identify all security-sensitive areas: trust boundaries, authentication, "
        "authorization, cryptography, data handling, and external integrations. "
        "Produce a priority table covering the whole repository."
    ),
    "threat-model": (
        DISCOVERY_PREFIX
        + "Evaluate the security design of the {repo_id} repository ({lang}). "
        "Identify missing security controls using the STRIDE-based checklist: "
        "trust boundaries, data flows, access control, abuse prevention, "
        "repudiation, resource limits, and external boundaries. Reference "
        "specific files and directories from the repository, not generic advice."
    ),
    "security-review": (
        DISCOVERY_PREFIX
        + "Produce a security findings report for the {repo_id} repository "
        "({lang}). For each finding include: severity, file:line, description, "
        "and recommended fix. Do not modify any files — output the report only. "
        "Cover the full repository, not just one directory."
    ),
}

# ---------------------------------------------------------------------------
# Judge prompts — sonnet, with tools enabled, cwd = repo_dir
# ---------------------------------------------------------------------------

JUDGE_SYSTEM = (
    "You are a rigorous evaluator for security analysis tools. You have Read, "
    "Glob, and Grep tools available and the repository is your current working "
    "directory. When the response makes claims about specific files or lines, "
    "you MUST open those files and verify the claim against the actual code. "
    "Do not invent verification steps you did not perform. Output only valid "
    "JSON, no prose."
)

_COMMON_JUDGE_SCHEMA = """\
Output JSON only:
{{
  "passed": <bool>,
  "clarity": <int 1-5>,
  "clarity_notes": "<one sentence>",
  "finding_validity": {{
    "checked": <int, how many findings you opened files to verify>,
    "verified": <int, how many matched the actual code>,
    "notes": "<brief>"
  }},
  "hotspot_coverage": {{
    "hotspots_total": <int or null>,
    "hotspots_addressed": <int or null>,
    "notes": "<brief or null>"
  }},
  "early_exit_pass": <bool>,
  "directories_covered": <int>,
  "verdict": "<1-2 sentences on why passed/failed>"
}}

Pass rule: passed=true iff clarity>=4 AND early_exit_pass AND (if
finding_validity.checked>0 then verified/checked>=0.7) AND (if
hotspot_coverage.hotspots_total is not null then
hotspot_coverage.hotspots_addressed/hotspot_coverage.hotspots_total>=0.5)."""

JUDGE_PROMPT_HOTSPOTS = """\
A hotspots analysis was run on the {repo_id} repository ({lang}).

RESPONSE:
{response}

Evaluate:

1. CLARITY (1-5): Is a priority table present with Priority/Category/File/Lines
   columns? Are rows actionable and specific? 5 = publication-quality, 1 =
   unusable. Also check that an architecture summary precedes the table.

2. FINDING_VALIDITY: For EVERY row in the priority table (up to 30 max —
   if there are more, pick 30 representative rows across categories), use
   Read on the cited file at the cited line range and confirm the code
   matches the category. Do not sample — the goal is real precision, not
   an estimate. Report verified/checked.

3. EARLY_EXIT: Count distinct top-level directories referenced in the response.
   Pass if >= 3.

hotspot_coverage fields should be null (not applicable to this skill).

""" + _COMMON_JUDGE_SCHEMA

JUDGE_PROMPT_THREAT_MODEL = """\
A threat model was produced for the {repo_id} repository ({lang}). This is a
design review, not a code review — it identifies missing controls.

RESPONSE:
{response}

Evaluate:

1. CLARITY (1-5): Are STRIDE categories covered (trust boundaries, data flows,
   access control, abuse prevention, repudiation, resource limits, external
   boundaries)? Are gaps specific and actionable? 5 = publication-quality.

2. FINDING_VALIDITY: For EVERY claim that references a specific file or
   directory (up to 30 max), use Glob/Read to confirm the path exists and
   that the claim about what is (or isn't) there is accurate. A
   threat-model claim like "no rate limiting on login" should be checkable
   by reading the login handler. Do not sample. Report verified/checked.

3. EARLY_EXIT: Count distinct top-level directories referenced. Pass if >= 3.

hotspot_coverage fields should be null (not applicable).

""" + _COMMON_JUDGE_SCHEMA

JUDGE_PROMPT_SECURITY_REVIEW = """\
A security review was run on the {repo_id} repository ({lang}). A hotspots
analysis for the same repo is included below as dynamic ground truth of where
the review *should* have looked.

HOTSPOTS ANALYSIS (ground truth):
{hotspots_response}

SECURITY REVIEW RESPONSE:
{response}

Evaluate:

1. CLARITY (1-5): Is there a findings table with severity, file:line,
   description, and recommended fix? Is each finding actionable? 5 =
   publication-quality.

2. FINDING_VALIDITY: For EVERY finding in the review (up to 30 max), use
   Read on the cited file at the cited line and confirm the vulnerable
   pattern is actually present. Be strict — if the claim is
   "timing-unsafe comparison" but the code uses
   `crypto/subtle.ConstantTimeCompare`, it does not verify. Do not sample.
   Report verified/checked.

3. HOTSPOT_COVERAGE: Extract the Critical+High priority rows from the hotspots
   analysis above. Count how many of those hotspot areas are addressed in the
   security review (either with a finding or with an explicit "reviewed, no
   issue"). Report hotspots_addressed/hotspots_total.

4. EARLY_EXIT: Count distinct top-level directories referenced in the review.
   Pass if >= 3.

""" + _COMMON_JUDGE_SCHEMA

JUDGE_PROMPTS = {
    "hotspots": JUDGE_PROMPT_HOTSPOTS,
    "threat-model": JUDGE_PROMPT_THREAT_MODEL,
    "security-review": JUDGE_PROMPT_SECURITY_REVIEW,
}


# ---------------------------------------------------------------------------
# Claude CLI
# ---------------------------------------------------------------------------

def claude_call(
    user_prompt: str,
    system_prompt: str,
    model: str = DEFAULT_MODEL,
    cwd: Path | None = None,
    timeout: int = 900,
    allowed_tools: str | None = None,
    plugin_dir: Path | None = None,
    max_budget_usd: float = 1.0,
) -> str:
    return run_claude(
        user_prompt,
        system_prompt,
        model=model,
        cwd=cwd,
        allowed_tools=allowed_tools,
        disable_tools=(cwd is None and allowed_tools is None),
        timeout=timeout,
        plugin_dir=plugin_dir,
        max_budget_usd=max_budget_usd,
    )


# ---------------------------------------------------------------------------
# Repo management
# ---------------------------------------------------------------------------

def clone_repo(repo_id: str, repo_url: str) -> Path:
    repos_dir = CACHE_DIR / "repos"
    repos_dir.mkdir(parents=True, exist_ok=True)
    repo_dir = repos_dir / repo_id

    if repo_dir.exists():
        print(f"  Using cached clone: {repo_dir}")
        subprocess.run(
            ["git", "-C", str(repo_dir), "pull", "--ff-only", "-q"],
            capture_output=True,
        )
        return repo_dir

    url = f"https://github.com/{repo_url}.git"
    print(f"  Cloning {url}...", end=" ", flush=True)
    result = subprocess.run(
        ["git", "clone", "--depth", "1", "-q", url, str(repo_dir)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"FAILED\n  {result.stderr.strip()}")
        return repo_dir
    print("done")
    return repo_dir


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def extract_json(text: str) -> str:
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        return fenced.group(1)
    bare = re.search(r"\{.*\}", text, re.DOTALL)
    return bare.group(0) if bare else text


def fmt_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    return f"{seconds / 60:.1f}m"


# ---------------------------------------------------------------------------
# Review + Judge
# ---------------------------------------------------------------------------

def run_review(
    skill_name: str, repo_info: dict, repo_dir: Path, model: str,
) -> tuple[str, float]:
    skill_path = SKILLS_DIR / skill_name / "SKILL.md"
    skill_content = skill_path.read_text(encoding="utf-8")
    user_prompt = REVIEW_PROMPTS[skill_name].format(
        repo_id=repo_info["id"], lang=repo_info["lang"],
    )
    # security-review is a subagent-orchestration skill — lock the main
    # loop to just Agent so it cannot do inline Read/Grep/Bash. Subagents
    # get the default toolset and do the actual work. hotspots and
    # threat-model do their analysis inline, so they need the default
    # toolset on the main process.
    #
    # The orchestrator dispatches named subagents (threat-modeling,
    # hotspot-mapping, design-review, vulnerability-audit,
    # attack-chain-analysis). Those live at <soundcheck>/agents/ but cwd
    # is the target repo, so we pass --plugin-dir pointing at the
    # soundcheck checkout to make them discoverable.
    allowed_tools = "Agent" if skill_name == "security-review" else None
    plugin_dir = ROOT if skill_name == "security-review" else None
    # The orchestrator fans out into 5+ subagent calls (one threat-model,
    # one hotspot map, 1b + N audit chunks, one attack-chain pass). All of
    # those bill against the same --max-budget-usd envelope, so the $1
    # default is far too tight; bump to $10 for security-review and stretch
    # the timeout to 40 minutes to give the pipeline room.
    if skill_name == "security-review":
        max_budget_usd = 10.0
        timeout = 2400
    else:
        max_budget_usd = 1.0
        timeout = 1200
    print(f"  Running review: {skill_name} ({model}) in {repo_dir.name}...",
          end=" ", flush=True)
    start = time.perf_counter()
    response = claude_call(
        user_prompt, skill_content, model=model, cwd=repo_dir, timeout=timeout,
        allowed_tools=allowed_tools,
        plugin_dir=plugin_dir,
        max_budget_usd=max_budget_usd,
    )
    elapsed = time.perf_counter() - start
    print(f"done ({fmt_duration(elapsed)})")
    return response, elapsed


def run_judge(
    skill_name: str, repo_info: dict, repo_dir: Path,
    review_response: str, hotspots_response: str | None,
) -> dict:
    template = JUDGE_PROMPTS[skill_name]
    fmt_args = {
        "repo_id": repo_info["id"],
        "lang": repo_info["lang"],
        "response": review_response,
    }
    if skill_name == "security-review":
        fmt_args["hotspots_response"] = hotspots_response or "(not available)"
    prompt = template.format(**fmt_args)

    print(f"  Judging:        {skill_name} ({JUDGE_MODEL})...",
          end=" ", flush=True)
    start = time.perf_counter()
    judge_text = claude_call(
        prompt, JUDGE_SYSTEM, model=JUDGE_MODEL, cwd=repo_dir, timeout=1200,
    )
    elapsed = time.perf_counter() - start
    print(f"done ({fmt_duration(elapsed)})")

    try:
        return json.loads(extract_json(judge_text))
    except (json.JSONDecodeError, AttributeError):
        return {"passed": False, "verdict": "judge produced invalid JSON"}


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_result(result: dict) -> None:
    if "error" in result:
        print(f"  {result['repo']} x {result['skill']}: "
              f"ERROR - {result['error']}")
        return

    judge = result["judge"]
    status = "PASS" if judge.get("passed") else "FAIL"
    clarity = judge.get("clarity", "?")
    fv = judge.get("finding_validity", {})
    verified = fv.get("verified", 0)
    checked = fv.get("checked", 0)
    hc = judge.get("hotspot_coverage", {})
    hc_add = hc.get("hotspots_addressed")
    hc_total = hc.get("hotspots_total")
    dirs = judge.get("directories_covered", "?")
    review_time = fmt_duration(result["review_time"])

    line = (
        f"  {status:<4} clarity {clarity}/5  "
        f"findings {verified}/{checked}  "
        f"dirs {dirs}  "
        f"review {review_time}"
    )
    if hc_total:
        line += f"  hotspot_cov {hc_add}/{hc_total}"
    print(line)

    if not judge.get("passed"):
        verdict = judge.get("verdict", "")
        if verdict:
            print(f"    → {verdict[:200]}")


def print_aggregate(all_results: list[dict]) -> None:
    valid = [r for r in all_results if "error" not in r]
    if not valid:
        print("No valid results to aggregate.")
        return

    total = len(valid)
    passed = sum(1 for r in valid if r["judge"].get("passed"))

    print("=" * 72)
    print(f"AGGREGATE  {passed}/{total} passed")

    # By skill
    print("\nBy skill:")
    for skill in SKILLS:
        sr = [r for r in valid if r["skill"] == skill]
        if not sr:
            continue
        s_passed = sum(1 for r in sr if r["judge"].get("passed"))
        clarities = [r["judge"].get("clarity", 0) for r in sr]
        avg_clarity = sum(clarities) / len(clarities) if clarities else 0
        avg_time = sum(r["review_time"] for r in sr) / len(sr)
        print(f"  {skill:<20} {s_passed}/{len(sr)} passed  "
              f"avg clarity {avg_clarity:.1f}/5  "
              f"avg time {fmt_duration(avg_time)}")

    # By repo
    print("\nBy repo:")
    for repo_info in REPO_MANIFEST:
        rr = [r for r in valid if r["repo"] == repo_info["id"]]
        if not rr:
            continue
        r_passed = sum(1 for r in rr if r["judge"].get("passed"))
        total_time = sum(r["review_time"] for r in rr)
        print(f"  {repo_info['id']:<20} {r_passed}/{len(rr)} passed  "
              f"total time {fmt_duration(total_time)}")

    # Finding validity
    total_checked = sum(
        r["judge"].get("finding_validity", {}).get("checked", 0) for r in valid
    )
    total_verified = sum(
        r["judge"].get("finding_validity", {}).get("verified", 0) for r in valid
    )
    if total_checked:
        rate = total_verified / total_checked * 100
        print(f"\nFinding validity: {total_verified}/{total_checked} "
              f"verified ({rate:.0f}%)")

    total_time = sum(r["review_time"] for r in valid)
    print(f"Total review time: {fmt_duration(total_time)}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluation benchmark for holistic Soundcheck skills"
    )
    parser.add_argument("--repo", metavar="NAME", help="Run a single repo")
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help=f"Review model (default: {DEFAULT_MODEL})")
    parser.add_argument("--verbose", action="store_true",
                        help="Print review and judge responses")
    parser.add_argument("--no-clone", action="store_true",
                        help="Skip git ops; use cached repos")
    args = parser.parse_args()

    repos = REPO_MANIFEST
    if args.repo:
        repos = [r for r in repos if r["id"] == args.repo]
        if not repos:
            print(f"Unknown repo: {args.repo}")
            print(f"Available: {[r['id'] for r in REPO_MANIFEST]}")
            return 1

    total = len(repos) * len(SKILLS)
    print(f"\nSoundcheck Eval Benchmark — {len(repos)} repo(s) x "
          f"{len(SKILLS)} skills = {total} evaluations")
    print(f"Review model: {args.model}   Judge model: {JUDGE_MODEL}\n")

    all_results: list[dict] = []
    bench_start = time.perf_counter()

    for repo_info in repos:
        repo_id = repo_info["id"]
        print("=" * 72)
        print(f"Repository: {repo_id} ({repo_info['lang']})")

        if args.no_clone:
            repo_dir = CACHE_DIR / "repos" / repo_id
        else:
            repo_dir = clone_repo(repo_id, repo_info["repo"])

        if not repo_dir.exists():
            print(f"  ERROR: repo not found at {repo_dir}")
            for skill in SKILLS:
                all_results.append({
                    "repo": repo_id, "skill": skill,
                    "error": "repo not cloned",
                })
            continue

        hotspots_response: str | None = None

        for skill_name in SKILLS:
            print(f"\n  {repo_id} x {skill_name}")
            try:
                review_response, review_time = run_review(
                    skill_name, repo_info, repo_dir, args.model,
                )
                if skill_name == "hotspots":
                    hotspots_response = review_response

                judge = run_judge(
                    skill_name, repo_info, repo_dir,
                    review_response, hotspots_response,
                )
                result = {
                    "repo": repo_id,
                    "skill": skill_name,
                    "review_time": review_time,
                    "judge": judge,
                }
                if args.verbose:
                    print(f"\n--- Review ---\n{review_response[:2000]}")
                    print(f"\n--- Judge ---\n{json.dumps(judge, indent=2)[:2000]}")
            except (RuntimeError, subprocess.TimeoutExpired) as exc:
                print(f"  ERROR: {exc}")
                result = {
                    "repo": repo_id, "skill": skill_name,
                    "error": str(exc)[:200],
                }
            print_result(result)
            all_results.append(result)
        print()

    print_aggregate(all_results)
    print(f"Wall clock: {fmt_duration(time.perf_counter() - bench_start)}")

    valid = [r for r in all_results if "error" not in r]
    all_passed = all(r["judge"].get("passed") for r in valid) if valid else False
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
