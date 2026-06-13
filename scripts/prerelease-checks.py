#!/usr/bin/env python3
"""Pre-release sanity check — verify README claims against repo state.

Catches the class of bug we just hit (README says "52 skills" but the
count drifted, says "130 fixtures" but smoke-test fixed at 134, etc).
Runs the static, free checks. Does NOT run paid benchmarks; those should
be re-checked manually before a release that touches skill bodies or
benchmark scripts.

Exits non-zero on any claim mismatch so a release pipeline can gate on it.

Usage::

    python scripts/prerelease-checks.py
    python scripts/prerelease-checks.py --verbose

Add to release.py's preflight (or run by hand before tagging).
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
SKILLS_DIR = ROOT / ".claude" / "skills"
SCRIPTS_DIR = ROOT / "scripts"


class Checker:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.warnings: list[str] = []

    def fail(self, msg: str) -> None:
        self.failures.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)


def check_skill_count(c: Checker, readme: str) -> None:
    """Every "N skills" mention in the README must match what's on disk."""
    actual = sum(1 for p in SKILLS_DIR.iterdir()
                 if p.is_dir() and (p / "SKILL.md").exists())
    # Match patterns like "52 skills", "the 52 skills", "All 52 skills"
    pattern = re.compile(r"\b(\d+)\s+skills\b")
    claims = pattern.findall(readme)
    if not claims:
        c.warn("README has no '<N> skills' claim — odd but not fatal")
        return
    bad = [n for n in claims if int(n) != actual]
    if bad:
        c.fail(
            f"README claims '{bad[0]} skills' in {len(bad)} place(s); "
            f"actual count under .claude/skills/ is {actual}"
        )


def check_referenced_scripts_exist(c: Checker, readme: str) -> None:
    """Every `python scripts/<name>.py` in the README must exist on disk."""
    pattern = re.compile(r"python\s+(scripts/[A-Za-z0-9_\-]+\.py)")
    referenced = set(pattern.findall(readme))
    missing = [r for r in referenced if not (ROOT / r).is_file()]
    if missing:
        c.fail(
            "README references scripts that don't exist on disk:\n  "
            + "\n  ".join(missing)
        )


def check_referenced_skill_names_exist(c: Checker, readme: str) -> None:
    """`<skill-name>` mentions in the trigger-reference table must match
    actual skill directory names. Catches renames."""
    # Pull skill names out of the trigger reference table — the rows look
    # like `| ... | \`<skill-name>\` | <OWASP> |`.
    pattern = re.compile(r"\|\s*`([a-z0-9-]+)`\s*\|\s*[A-Z]")
    referenced = set(pattern.findall(readme))
    # Filter to plausible skill names (also pulls some OWASP tags, etc;
    # we only validate against what's in skills/).
    on_disk = {p.name for p in SKILLS_DIR.iterdir() if p.is_dir()}
    bogus = [r for r in referenced
             if r not in on_disk and r not in {"pr-review", "security-review",
                                                "contract-review", "security-cleanup",
                                                "threat-model", "hotspots"}]
    # Skip — pattern is too broad; we end up matching CWE/severity strings.
    # Leave this as a no-op for now; a future improvement would parse the
    # table more carefully. Keeping the function as a placeholder.
    _ = bogus


def check_required_doc_files(c: Checker, readme: str) -> None:
    """Every `[link](docs/foo.md)` or `[link](path/to/file.md)` in the README
    must exist on disk."""
    pattern = re.compile(r"\]\(([^)]+\.md)\)")
    missing = []
    for ref in set(pattern.findall(readme)):
        if ref.startswith("http"):
            continue
        # Strip anchors, e.g. docs/contract-review.md#hit-rate
        path = ref.split("#")[0]
        if not (ROOT / path).is_file():
            missing.append(ref)
    if missing:
        c.fail(
            "README links to docs that don't exist:\n  "
            + "\n  ".join(missing)
        )


def check_skill_word_counts(c: Checker) -> None:
    """Run scripts/validate-skills.py and surface failures."""
    r = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "validate-skills.py")],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        c.fail(
            "validate-skills.py exited non-zero:\n  "
            + r.stdout.strip().splitlines()[-3:-1].__repr__()
        )


def check_hooks(c: Checker) -> None:
    """Run scripts/validate-hooks.py and surface failures."""
    r = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "validate-hooks.py")],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        c.fail(f"validate-hooks.py exited non-zero:\n  {r.stdout.strip()}")


def check_plugin_manifest(c: Checker) -> None:
    """Run claude plugin validate against plugin.json directly."""
    manifest = ROOT / ".claude-plugin" / "plugin.json"
    r = subprocess.run(
        ["claude", "plugin", "validate", str(manifest)],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        c.fail(
            f"claude plugin validate exited {r.returncode}:\n  "
            + (r.stdout or r.stderr).strip()
        )


def check_paid_benchmark_freshness(c: Checker) -> None:
    """Warn if the latest commit touched skill bodies or benchmark scripts
    but the README's numeric claims haven't been re-verified. This is a
    *warning* not a failure — we don't want to gate every commit on a
    paid benchmark run."""
    pattern = re.compile(
        r"\.claude/skills/.*/SKILL\.md|"
        r"\.claude/agents/.*\.md|"
        r"scripts/benchmark-.*\.py|"
        r"scripts/smoke-test-skills\.py"
    )
    r = subprocess.run(
        ["git", "log", "--since=7.days", "--name-only", "--pretty=format:"],
        cwd=ROOT, capture_output=True, text=True,
    )
    touched = [ln for ln in r.stdout.splitlines() if pattern.match(ln)]
    if touched:
        c.warn(
            "Skill bodies or benchmark scripts changed in the last 7 days. "
            "If the README's quoted numbers (smoke pass rates, validity %, "
            "review times) might be stale, re-run:\n"
            "  python scripts/smoke-test-skills.py (~2h)\n"
            "  python scripts/benchmark-eval.py (~100min)\n"
            "  python scripts/benchmark-realworld.py (~30min)\n"
            "Touched files: " + ", ".join(sorted(set(touched))[:5])
        )


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    c = Checker()
    readme = README.read_text()

    checks = [
        ("skill count", lambda: check_skill_count(c, readme)),
        ("referenced scripts exist", lambda: check_referenced_scripts_exist(c, readme)),
        ("referenced docs exist", lambda: check_required_doc_files(c, readme)),
        ("skill validators", lambda: check_skill_word_counts(c)),
        ("hook validator", lambda: check_hooks(c)),
        ("plugin manifest", lambda: check_plugin_manifest(c)),
        ("paid-benchmark freshness", lambda: check_paid_benchmark_freshness(c)),
    ]
    for name, fn in checks:
        before_fail = len(c.failures)
        before_warn = len(c.warnings)
        try:
            fn()
        except Exception as exc:
            c.fail(f"[{name}] check itself raised: {exc!r}")
            continue
        status = "FAIL" if len(c.failures) > before_fail else (
            "WARN" if len(c.warnings) > before_warn else "OK"
        )
        if args.verbose or status != "OK":
            print(f"  {status}  {name}")

    print()
    if c.warnings:
        print(f"warnings: {len(c.warnings)}")
        for w in c.warnings:
            print(f"  ⚠ {w}")
        print()
    if c.failures:
        print(f"FAILED: {len(c.failures)} check(s)")
        for f in c.failures:
            print(f"  ✗ {f}")
        return 1
    print("OK — all prerelease checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
