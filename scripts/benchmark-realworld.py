#!/usr/bin/env python3
"""
Real-world validation benchmark for Soundcheck skills.

Tests Soundcheck skills against files extracted from intentionally vulnerable
open-source applications at pinned commits:
- OWASP Juice Shop (TypeScript/Node.js) — github.com/juice-shop/juice-shop
- OWASP PyGoat (Python/Django)          — github.com/adeyosemanputra/pygoat

Files are fetched via the GitHub raw API and cached locally. The same
LLM-as-judge pattern used in benchmark-securityeval.py is applied:
each file is reviewed with the relevant skill as context, then a judge
evaluates DETECTION, CATEGORIZATION, and FIX.

Usage:
    python scripts/benchmark-realworld.py
    python scripts/benchmark-realworld.py --skill injection
    python scripts/benchmark-realworld.py --verbose
    python scripts/benchmark-realworld.py --no-cache

Cost estimate: ~20 files × 2 calls × ~1000 tokens ≈ $0.05–0.10 per full run
               Runtime: ~3 minutes at 2s inter-call delay
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
CACHE_DIR = ROOT / ".realworld-cache"
MAX_FILE_BYTES = 50_000  # truncate files > 50 KB

# Overridden by --skills-dir; resolved in main().
SKILLS_DIR: Path = ROOT / "skills"

# Files from intentionally vulnerable applications, pinned to specific commits.
# Each entry maps a single file to the Soundcheck skill best positioned to catch it.
MANIFEST = [
    # ── OWASP Juice Shop (TypeScript/Node.js) ────────────────────────────
    # Commit: 8262a6a — Mar 23, 2026
    {
        "id": "juice-shop/routes/search.ts",
        "repo": "juice-shop/juice-shop",
        "commit": "8262a6a5b1686df7acbe451943b704e53b250c6b",
        "path": "routes/search.ts",
        "skill": "injection",
        "description": "SQL injection via unparameterized query on user-supplied search term",
    },
    {
        "id": "juice-shop/routes/login.ts",
        "repo": "juice-shop/juice-shop",
        "commit": "8262a6a5b1686df7acbe451943b704e53b250c6b",
        "path": "routes/login.ts",
        "skill": "injection",
        "description": "SQL injection in authentication — email/password passed directly into query string",
    },
    {
        "id": "juice-shop/routes/updateProductReviews.ts",
        "repo": "juice-shop/juice-shop",
        "commit": "8262a6a5b1686df7acbe451943b704e53b250c6b",
        "path": "routes/updateProductReviews.ts",
        "skill": "injection",
        "description": "NoSQL injection — batch update with unfiltered user-supplied selector",
    },
    {
        "id": "juice-shop/lib/insecurity.ts",
        "repo": "juice-shop/juice-shop",
        "commit": "8262a6a5b1686df7acbe451943b704e53b250c6b",
        "path": "lib/insecurity.ts",
        "skill": "cryptographic-failures",
        "description": "Hardcoded RSA private key and HMAC secret, MD5 hashing, weak JWT verification",
    },
    {
        "id": "juice-shop/routes/redirect.ts",
        "repo": "juice-shop/juice-shop",
        "commit": "8262a6a5b1686df7acbe451943b704e53b250c6b",
        "path": "routes/redirect.ts",
        "skill": "broken-access-control",
        "description": "Open redirect — allowlist check uses substring matching instead of exact URL comparison",
    },
    {
        "id": "juice-shop/routes/payment.ts",
        "repo": "juice-shop/juice-shop",
        "commit": "8262a6a5b1686df7acbe451943b704e53b250c6b",
        "path": "routes/payment.ts",
        "skill": "broken-access-control",
        "description": "IDOR — client-controlled UserId in request body allows acting as any user",
    },
    {
        "id": "juice-shop/routes/profileImageUrlUpload.ts",
        "repo": "juice-shop/juice-shop",
        "commit": "8262a6a5b1686df7acbe451943b704e53b250c6b",
        "path": "routes/profileImageUrlUpload.ts",
        "skill": "broken-access-control",
        "description": "SSRF — arbitrary URL fetch with insufficient destination validation",
    },
    {
        "id": "juice-shop/routes/resetPassword.ts",
        "repo": "juice-shop/juice-shop",
        "commit": "8262a6a5b1686df7acbe451943b704e53b250c6b",
        "path": "routes/resetPassword.ts",
        "skill": "authentication-failures",
        "description": "No rate limiting on password reset, hardcoded security answers, info disclosure via error messages",
    },
    {
        "id": "juice-shop/routes/fileUpload.ts",
        "repo": "juice-shop/juice-shop",
        "commit": "8262a6a5b1686df7acbe451943b704e53b250c6b",
        "path": "routes/fileUpload.ts",
        "skill": "integrity-failures",
        "description": "Unsafe deserialization — YAML and XML uploads parsed without content restriction",
    },
    {
        "id": "juice-shop/routes/logfileServer.ts",
        "repo": "juice-shop/juice-shop",
        "commit": "8262a6a5b1686df7acbe451943b704e53b250c6b",
        "path": "routes/logfileServer.ts",
        "skill": "broken-access-control",
        "description": "Path traversal — log file served with only a forward-slash presence check",
    },
    # ── OWASP PyGoat (Python/Django) ─────────────────────────────────────
    # Commit: 2fb0c60 — Feb 1, 2026
    {
        "id": "pygoat/introduction/views.py",
        "repo": "adeyosemanputra/pygoat",
        "commit": "2fb0c600245f50670e8b9233c784afe61e8b340b",
        "path": "introduction/views.py",
        "skill": "injection",
        "description": "SQL injection, eval() code execution, and command injection in Django lab views",
    },
    {
        "id": "pygoat/dockerized_labs/broken_auth_lab/app.py",
        "repo": "adeyosemanputra/pygoat",
        "commit": "2fb0c600245f50670e8b9233c784afe61e8b340b",
        "path": "dockerized_labs/broken_auth_lab/app.py",
        "skill": "authentication-failures",
        "description": "Hardcoded credentials, weak base64 session tokens, plaintext passwords, MD5 password-reset tokens",
    },
    {
        "id": "pygoat/introduction/playground/ssrf/main.py",
        "repo": "adeyosemanputra/pygoat",
        "commit": "2fb0c600245f50670e8b9233c784afe61e8b340b",
        "path": "introduction/playground/ssrf/main.py",
        "skill": "broken-access-control",
        "description": "Path traversal via unvalidated os.path.join() with user-supplied filename",
    },
]

REVIEW_PROMPT = (
    "Review this file for security issues. "
    "Identify all vulnerabilities and rewrite any insecure code."
)

JUDGE_SYSTEM = (
    "You are a precise test evaluator for a security code review system. "
    "Evaluate whether a review response satisfies each criterion. "
    "Be strict but fair. Output only valid JSON, no prose."
)

JUDGE_PROMPT = """\
This file is from an intentionally vulnerable application. It is known to \
contain at least one vulnerability in the {skill} category: {description}

Evaluate whether the security review response satisfies all three criteria:

1. DETECTION: The response identifies at least one security vulnerability in this code.
2. CATEGORIZATION: The response correctly identifies at least one real vulnerability \
type present (e.g., SQL injection, path traversal, weak crypto). It does not need to \
name the exact CWE — correctly describing the vulnerability class is sufficient.
3. FIX: The response proposes a concrete secure fix. A full rewrite, a corrected code \
snippet, or a specific one-line change showing the correct API call all count. Generic \
advice without code ("use parameterized queries", "validate input") does NOT count. \
Showing the actual corrected call does count.

File reviewed:
```
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


def raw_url(repo: str, commit: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{commit}/{path}"


def fetch_file(entry: dict, no_cache: bool) -> str | None:
    """Download a file from GitHub at a pinned commit, with local caching."""
    cache_key = entry["id"].replace("/", "_")
    cache_path = CACHE_DIR / cache_key
    if not no_cache and cache_path.exists():
        return cache_path.read_text(encoding="utf-8", errors="replace")

    url = raw_url(entry["repo"], entry["commit"], entry["path"])
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310
            raw = resp.read()
    except Exception as exc:
        print(f"  [skip] could not fetch {url}: {exc}", file=sys.stderr)
        return None

    content = raw.decode("utf-8", errors="replace")
    if len(raw) > MAX_FILE_BYTES:
        content = content[:MAX_FILE_BYTES] + "\n// [TRUNCATED — file exceeds 50 KB]"

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(content, encoding="utf-8")
    return content


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
                wait = int(float(retry_after)) if retry_after else 30 * (2 ** attempt)
                print(f"  [rate limited, retrying in {wait}s]", flush=True)
                time.sleep(wait)
            elif exc.status_code == 529 and attempt < max_retries - 1:
                wait = 2 ** attempt
                print(f"  [overloaded, retrying in {wait}s]", flush=True)
                time.sleep(wait)
            else:
                raise
    raise RuntimeError(f"api_call_with_retry: all {max_retries} attempts failed")


def run_entry(
    client: anthropic.Anthropic,
    skill_content: str,
    entry: dict,
    code: str,
    verbose: bool,
) -> dict:
    """Run one manifest entry through the skill and judge."""
    review_resp = api_call_with_retry(
        client,
        dict(
            model=MODEL,
            max_tokens=2048,
            system=skill_content,
            messages=[{"role": "user", "content": f"{REVIEW_PROMPT}\n\n```\n{code}\n```"}],
        ),
    )
    review_text = review_resp.content[0].text

    if verbose:
        print(f"\n  [review]\n  {review_text[:400]}{'...' if len(review_text) > 400 else ''}")

    judge_resp = api_call_with_retry(
        client,
        dict(
            model=MODEL,
            max_tokens=512,
            temperature=0,
            system=JUDGE_SYSTEM,
            messages=[{
                "role": "user",
                "content": JUDGE_PROMPT.format(
                    skill=entry["skill"],
                    description=entry["description"],
                    code=code,
                    response=review_text,
                ),
            }],
        ),
    )
    judge_text = judge_resp.content[0].text

    if verbose:
        print(f"  [judge] {judge_text}")

    try:
        result = json.loads(extract_json(judge_text))
    except (json.JSONDecodeError, AttributeError):
        result = {"passed": False, "criteria": []}

    return {
        "id": entry["id"],
        "skill": entry["skill"],
        "passed": result.get("passed", False),
        "criteria": result.get("criteria", []),
    }


def run_skill_benchmark(
    client: anthropic.Anthropic,
    skill_name: str,
    entries: list[dict],
    no_cache: bool,
    verbose: bool,
) -> dict:
    skill_path = SKILLS_DIR / skill_name / "SKILL.md"
    if not skill_path.exists():
        return {"skill": skill_name, "error": "SKILL.md not found"}

    skill_content = skill_path.read_text(encoding="utf-8")
    results = []

    for i, entry in enumerate(entries):
        if i > 0:
            time.sleep(2)

        code = fetch_file(entry, no_cache)
        if code is None:
            results.append({
                "id": entry["id"],
                "skill": skill_name,
                "passed": False,
                "criteria": [],
                "error": "fetch failed",
            })
            continue

        result = run_entry(client, skill_content, entry, code, verbose)
        results.append(result)

    total = len(results)
    passed = sum(1 for r in results if r.get("passed"))
    detected = sum(
        1 for r in results
        if any(c.get("criterion") == "DETECTION" and c.get("passed") for c in r.get("criteria", []))
    )
    fixed = sum(
        1 for r in results
        if any(c.get("criterion") == "FIX" and c.get("passed") for c in r.get("criteria", []))
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
            mark = "✓" if r.get("passed") else "✗"
            failed_criteria = [
                c["criterion"] for c in r.get("criteria", []) if not c.get("passed")
            ]
            err = f"  [{r['error']}]" if r.get("error") else ""
            suffix = f"  (failed: {', '.join(failed_criteria)})" if failed_criteria else ""
            print(f"    {mark} {r['id']}{suffix}{err}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Real-world validation benchmark for Soundcheck skills"
    )
    parser.add_argument("--skill", metavar="NAME", help="Benchmark a single skill")
    parser.add_argument("--verbose", action="store_true", help="Print review and judge responses")
    parser.add_argument("--no-cache", action="store_true", help="Re-download files even if cached")
    parser.add_argument(
        "--skills-dir", metavar="PATH",
        help="Directory containing skill subdirectories (default: repo skills/)",
    )
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY not set", file=sys.stderr)
        return 1

    global SKILLS_DIR
    if args.skills_dir:
        SKILLS_DIR = Path(args.skills_dir).resolve()
        if not SKILLS_DIR.is_dir():
            print(f"ERROR: --skills-dir not found: {SKILLS_DIR}", file=sys.stderr)
            return 1

    # Group manifest entries by skill
    groups: dict[str, list[dict]] = {}
    for entry in MANIFEST:
        groups.setdefault(entry["skill"], []).append(entry)

    if args.skill:
        if args.skill not in groups:
            print(f"No manifest entries for skill '{args.skill}'")
            print(f"Available skills: {sorted(groups)}")
            return 1
        skill_names = [args.skill]
    else:
        skill_names = sorted(groups)

    client = anthropic.Anthropic(api_key=api_key)
    total_files = sum(len(groups[s]) for s in skill_names)

    print(f"\nSoundcheck Real-World Benchmark — {len(skill_names)} skill(s), {total_files} files")
    print(f"Sources: OWASP Juice Shop (TypeScript), OWASP PyGoat (Python)")
    print(f"Model: {MODEL}\n")

    all_summaries = []
    for i, skill_name in enumerate(skill_names):
        if i > 0:
            time.sleep(1)
        entries = groups[skill_name]
        sources = sorted({e["repo"].split("/")[0] for e in entries})
        print(f"▶ {skill_name}  [{', '.join(sources)}]  {len(entries)} file(s)")
        summary = run_skill_benchmark(client, skill_name, entries, args.no_cache, args.verbose)
        print_skill_summary(summary, args.verbose)
        all_summaries.append(summary)
        print()

    # Aggregate
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
    print()

    weak = sorted(valid, key=lambda s: s["detection_rate"])[:3]
    if weak and weak[0]["detection_rate"] < 1.0:
        print("Lowest detection rates:")
        for s in weak:
            if s["detection_rate"] < 1.0:
                print(f"  {s['skill']:<28} {int(s['detection_rate'] * 100)}%")
        print()

    return 0 if total_passed == total_samples else 1


if __name__ == "__main__":
    sys.exit(main())
