#!/usr/bin/env python3
"""
Soundcheck auto-review — Stop hook driver.

Fires after Claude finishes a turn. Three stages before surfacing
findings to Claude:

  1. Local file-extension gate (~10ms): only proceed if at least one
     changed file matches the code-file allowlist.

  2. Haiku triage (~2-3s ideal, can run minutes on a heavily loaded
     session, ~$0.001 either way): one short claude -p call asking
     "does this diff need a security review?". Skips silently on NO or
     parse failure. No timeout — the script runs detached via
     asyncRewake, so a slow triage cannot block the user.

  3. Full pr-review (~30-60s on haiku): on triage YES, spawn
     security-review-action.py against the diff, surface findings to
     stderr, exit 2 (asyncRewake → wakes Claude).

Default-on. To disable, export SOUNDCHECK_AUTO_REVIEW=false in the shell
before launching Claude Code.

Earlier versions exposed an `autoReview` userConfig option, but
`CLAUDE_PLUGIN_OPTION_*` env vars are not actually exported to Stop hook
subprocesses for default-valued options (empirically verified by
scripts/test-hook-env.py). Removing the userConfig field keeps the
toggle behavior honest.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def _opted_out(v: str | None) -> bool:
    return (v or "").strip().lower() in ("0", "false", "no", "off")


if _opted_out(os.environ.get("SOUNDCHECK_AUTO_REVIEW")):
    sys.exit(0)

PROJECT_DIR = Path(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()).resolve()
PLUGIN_ROOT = Path(
    os.environ.get("CLAUDE_PLUGIN_ROOT") or Path(__file__).resolve().parent.parent
)
ACTION = PLUGIN_ROOT / "scripts" / "security-review-action.py"

CODE_EXT = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs",
    ".go", ".rs", ".java", ".kt", ".kts", ".scala",
    ".rb", ".php", ".cs", ".swift", ".m", ".mm",
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp",
    ".html", ".vue", ".svelte", ".ejs", ".hbs", ".erb",
    ".yml", ".yaml", ".toml", ".json", ".env",
    ".sh", ".bash", ".zsh", ".fish", ".ps1",
}

TRIAGE_INSTRUCTION = (
    "Below is a git diff of recent code edits. Reply with exactly one "
    "word: YES if the diff contains code that could plausibly introduce "
    "a security vulnerability — auth, session/CSRF, password/token/"
    "secret handling, crypto, SQL/NoSQL/template/shell injection sinks, "
    "user-controlled file/URL/network operations, deserialization of "
    "untrusted data, LLM prompt construction, access control, or "
    "significant logic changes near a trust boundary — or NO otherwise. "
    "Output only the single word."
)

def _git(*args: str) -> tuple[int, str]:
    r = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        cwd=PROJECT_DIR,
    )
    return r.returncode, r.stdout


def _gather() -> tuple[list[str], str]:
    """Return (changed_code_files, content_for_risk_check)."""
    rc, _ = _git("rev-parse", "--git-dir")
    if rc != 0:
        return [], ""

    rc, mod = _git("diff", "HEAD", "--name-only")
    modified = [f for f in mod.splitlines() if Path(f).suffix in CODE_EXT]

    rc, unt = _git("ls-files", "--others", "--exclude-standard")
    untracked = [f for f in unt.splitlines() if Path(f).suffix in CODE_EXT]

    files = modified + untracked
    if not files:
        return [], ""

    chunks: list[str] = []
    if modified:
        rc, diff = _git("diff", "HEAD", "--unified=0", "--", *modified)
        if rc == 0:
            chunks.extend(
                ln
                for ln in diff.splitlines()
                if ln.startswith("+") and not ln.startswith("+++")
            )
    for f in untracked:
        try:
            chunks.append((PROJECT_DIR / f).read_text(errors="replace"))
        except OSError:
            pass

    return files, "\n".join(chunks)


def _triage(content: str) -> bool:
    """One-shot haiku call: does this diff plausibly need a security review?

    No timeout — claude -p latency on a fully-loaded session can run into
    minutes (we observed ~108s on a routine call). The hook runs detached
    via asyncRewake, so a slow triage doesn't block the user.
    """
    try:
        r = subprocess.run(
            ["claude", "-p", "--model", "haiku",
             f"{TRIAGE_INSTRUCTION}\n\n{content}"],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return False
    if r.returncode != 0 or not r.stdout:
        return False
    first = r.stdout.strip().splitlines()[0].strip().upper() if r.stdout.strip() else ""
    return first.startswith("YES")


def main() -> int:
    triage_only = "--triage-only" in sys.argv

    if not PROJECT_DIR.is_dir():
        return 0
    if not triage_only and not ACTION.exists():
        return 0

    files, content = _gather()
    if not files or not content.strip():
        return 0

    if not _triage(content):
        return 0

    if triage_only:
        print("triage: YES", file=sys.stderr)
        return 2

    cmd = [
        sys.executable,
        str(ACTION),
        "--repo-dir",
        str(PROJECT_DIR),
        "--diff-base",
        "HEAD",
        "--model",
        "haiku",
        "--timeout",
        "180",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    out = proc.stdout or ""

    if "<soundcheck-findings>[]" in out or "<soundcheck-findings>" not in out:
        return 0

    print(
        "Soundcheck auto-review found issues in your recent edits. "
        "Address each finding or push back with a concrete reason.\n",
        file=sys.stderr,
    )
    print(out, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
