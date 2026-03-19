#!/usr/bin/env python3
"""
Run a Soundcheck security review against a repository and produce file rewrites.

Used by the soundcheck/security-review GitHub Action to:
  1. Collect source files from the repo
  2. Send them to Claude with the security-review skill as context
  3. Parse Critical/High/Medium findings and rewrite the affected files
  4. Write a findings summary to --output-summary for use in the PR body

Usage:
    python scripts/security-review-action.py --repo-dir /path/to/repo
    python scripts/security-review-action.py --repo-dir . --max-files 30
    python scripts/security-review-action.py --repo-dir . --skill-path skills/security-review/SKILL.md

Exit codes:
    0 — no Critical or High findings
    1 — Critical or High findings present (use to fail a blocking check)
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

import anthropic

SCRIPT_DIR = Path(__file__).parent
DEFAULT_SKILL_PATH = SCRIPT_DIR.parent / "skills" / "security-review" / "SKILL.md"

MODEL = "claude-sonnet-4-6"
MAX_FILE_BYTES = 50_000    # truncate files larger than 50 KB
MAX_TOTAL_BYTES = 200_000  # stop adding files after 200 KB total
DEFAULT_MAX_FILES = 50

SOURCE_GLOBS = [
    "**/*.py", "**/*.js", "**/*.ts", "**/*.go",
    "**/*.java", "**/*.rb", "**/*.php", "**/*.cs", "**/*.rs",
]
SKIP_DIRS = {"node_modules", ".venv", "venv", "dist", "build", ".git", "__pycache__"}

# Appended to the skill's own system prompt to request structured output.
SYSTEM_SUFFIX = """
---

After your findings table and prose rewrites, output all results in the following
machine-readable format so they can be applied automatically.

For each Critical, High, or Medium finding where you rewrote a file, output one block:

<soundcheck-rewrite file="relative/path/to/file">
complete rewritten file content — the full file, not a diff
</soundcheck-rewrite>

Then output a JSON findings list:

<soundcheck-findings>
[
  {
    "severity": "Critical|High|Medium|Low",
    "file": "relative/path/to/file",
    "skill": "skill-name",
    "finding": "one-line description"
  }
]
</soundcheck-findings>

Severity definitions:
- Critical: exploitable remotely, no authentication required
- High: exploitable with authentication, or significant data exposure
- Medium: limited exploitability or requires user interaction
- Low: defense-in-depth / informational
"""

USER_PROMPT_HEADER = """\
Review the following repository files for security issues. Identify all \
vulnerabilities. Rewrite every file that has a Critical, High, or Medium finding — \
output the complete rewritten file, not a diff.

"""


def collect_files(repo_dir: Path, max_files: int) -> list[tuple[str, str]]:
    """
    Glob source files from repo_dir, respecting size and count limits.
    Returns a list of (relative_path, content) tuples.
    """
    candidates: list[Path] = []
    seen: set[Path] = set()
    for pattern in SOURCE_GLOBS:
        for path in sorted(repo_dir.glob(pattern)):
            if any(skip in path.parts for skip in SKIP_DIRS):
                continue
            if path not in seen:
                seen.add(path)
                candidates.append(path)

    files: list[tuple[str, str]] = []
    total_bytes = 0
    for path in candidates:
        if len(files) >= max_files or total_bytes >= MAX_TOTAL_BYTES:
            break
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(content.encode()) > MAX_FILE_BYTES:
            content = content[:MAX_FILE_BYTES] + "\n# [TRUNCATED — file exceeds 50 KB]"
        rel = str(path.relative_to(repo_dir))
        files.append((rel, content))
        total_bytes += len(content.encode())

    return files


def build_user_prompt(files: list[tuple[str, str]]) -> str:
    parts = [USER_PROMPT_HEADER]
    for rel_path, content in files:
        ext = Path(rel_path).suffix.lstrip(".")
        parts.append(f"## {rel_path}\n```{ext}\n{content}\n```\n")
    return "\n".join(parts)


def parse_rewrites(response: str) -> dict[str, str]:
    """Extract <soundcheck-rewrite file="..."> blocks from the response."""
    pattern = re.compile(
        r'<soundcheck-rewrite\s+file="([^"]+)">\n(.*?)\n</soundcheck-rewrite>',
        re.DOTALL,
    )
    return {m.group(1): m.group(2) for m in pattern.finditer(response)}


def parse_findings(response: str) -> list[dict]:
    """Extract <soundcheck-findings> JSON array from the response."""
    match = re.search(
        r"<soundcheck-findings>\s*(\[.*?\])\s*</soundcheck-findings>",
        response,
        re.DOTALL,
    )
    if not match:
        return []
    try:
        return json.loads(match.group(1))
    except (json.JSONDecodeError, ValueError):
        return []


def apply_rewrites(repo_dir: Path, rewrites: dict[str, str]) -> list[str]:
    """
    Write rewritten content to disk.
    Skips any path that escapes the repo root (path traversal guard).
    Returns list of relative paths successfully written.
    """
    written: list[str] = []
    for rel_path, content in rewrites.items():
        target = (repo_dir / rel_path).resolve()
        if not target.is_relative_to(repo_dir.resolve()):
            print(f"  [skip] {rel_path} — path outside repo root", file=sys.stderr)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        written.append(rel_path)
        print(f"  [rewrite] {rel_path}")
    return written


def build_pr_body(findings: list[dict], rewritten: list[str], file_count: int) -> str:
    if not findings:
        return (
            "## Soundcheck Security Review\n\n"
            f"Scanned {file_count} file(s). No issues found. ✅\n\n"
            "_Generated by [Soundcheck](https://github.com/thejefflarson/soundcheck)_"
        )

    by_severity = {s: [] for s in ("Critical", "High", "Medium", "Low")}
    for f in findings:
        by_severity.setdefault(f.get("severity", "Low"), []).append(f)

    icons = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵"}
    total = len(findings)
    lines = [
        "## Soundcheck Security Review",
        "",
        f"Scanned **{file_count}** file(s) · "
        f"Found **{total}** issue(s) · "
        f"Rewrote **{len(rewritten)}** file(s)",
        "",
        "| Severity | File | Skill | Finding |",
        "|----------|------|-------|---------|",
    ]
    for severity in ("Critical", "High", "Medium", "Low"):
        for f in by_severity[severity]:
            icon = icons[severity]
            file_ = f"`{f.get('file', '—')}`" if f.get("file") else "—"
            skill = f"`{f.get('skill', '—')}`" if f.get("skill") else "—"
            lines.append(
                f"| {icon} {severity} | {file_} | {skill} | {f.get('finding', '—')} |"
            )

    if rewritten:
        lines += ["", "### Files rewritten in this PR", ""]
        for p in rewritten:
            lines.append(f"- `{p}`")

    lines += [
        "",
        "---",
        "_Generated by [Soundcheck](https://github.com/thejefflarson/soundcheck)_",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Soundcheck security review and write file rewrites to disk"
    )
    parser.add_argument(
        "--repo-dir", metavar="PATH", default=".",
        help="Repository root to scan (default: current directory)",
    )
    parser.add_argument(
        "--skill-path", metavar="PATH", default=str(DEFAULT_SKILL_PATH),
        help="Path to security-review SKILL.md",
    )
    parser.add_argument(
        "--max-files", type=int, default=DEFAULT_MAX_FILES, metavar="N",
        help=f"Max source files to include in review (default: {DEFAULT_MAX_FILES})",
    )
    parser.add_argument(
        "--output-summary", metavar="PATH", default="/tmp/soundcheck-summary.md",
        help="Write PR body markdown to this path (default: /tmp/soundcheck-summary.md)",
    )
    parser.add_argument(
        "--model", default=MODEL,
        help=f"Claude model to use (default: {MODEL})",
    )
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY not set", file=sys.stderr)
        return 1

    repo_dir = Path(args.repo_dir).resolve()
    skill_path = Path(args.skill_path)
    if not skill_path.exists():
        print(f"ERROR: skill not found: {skill_path}", file=sys.stderr)
        return 1

    system_prompt = skill_path.read_text(encoding="utf-8") + SYSTEM_SUFFIX

    print(f"Collecting source files from {repo_dir} (max {args.max_files})...")
    files = collect_files(repo_dir, args.max_files)
    if not files:
        print("No source files found.")
        return 0
    total_kb = sum(len(c.encode()) for _, c in files) // 1024
    print(f"Collected {len(files)} file(s) ({total_kb} KB). Sending to {args.model}...")

    client = anthropic.Anthropic(api_key=api_key)
    response = client.messages.create(
        model=args.model,
        max_tokens=8192,
        system=system_prompt,
        messages=[{"role": "user", "content": build_user_prompt(files)}],
    )
    response_text = response.content[0].text

    findings = parse_findings(response_text)
    rewrites = parse_rewrites(response_text)

    critical_high = [f for f in findings if f.get("severity") in ("Critical", "High")]
    medium = [f for f in findings if f.get("severity") == "Medium"]
    print(f"\nFindings: {len(findings)} "
          f"({len(critical_high)} Critical/High, {len(medium)} Medium) · "
          f"Rewrites: {len(rewrites)}")

    rewritten = apply_rewrites(repo_dir, rewrites)

    summary = build_pr_body(findings, rewritten, len(files))
    Path(args.output_summary).write_text(summary, encoding="utf-8")
    print(f"\nPR summary written to {args.output_summary}")
    print("\n" + summary)

    return 1 if critical_high else 0


if __name__ == "__main__":
    sys.exit(main())
