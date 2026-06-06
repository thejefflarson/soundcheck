#!/usr/bin/env python3
"""
Soundcheck auto-review — Stop hook driver.

Fires after Claude finishes a turn. Three stages before surfacing
findings to Claude:

  1. Local file-extension gate (~10ms): only proceed if at least one
     changed file matches the code-file allowlist.

  2. Haiku triage (~3s warm, ~30s+ cold start, ~$0.003 per call):
     one short claude -p call asking "does this diff need a security
     review?". The cost and latency come from claude -p loading every
     enabled plugin's system prompt (~30K cached tokens) on each
     invocation. Skips silently on NO or parse failure. No timeout —
     the script runs detached via asyncRewake, so a slow triage cannot
     block the user.

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

import fcntl
import hashlib
import json
import os
import subprocess
import sys
import time
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

# Per-project state directory under CLAUDE_PLUGIN_DATA (the docs-guaranteed
# persistent location). Falls back to /tmp if the env var is missing.
_STATE_BASE = Path(
    os.environ.get("CLAUDE_PLUGIN_DATA")
    or os.environ.get("TMPDIR", "/tmp")
)
_PROJECT_KEY = hashlib.sha256(str(PROJECT_DIR).encode()).hexdigest()[:16]
LOCK_PATH = _STATE_BASE / f"auto-review-{_PROJECT_KEY}.lock"
STATE_PATH = _STATE_BASE / f"auto-review-{_PROJECT_KEY}.state.json"
STATE_TTL_SECONDS = 24 * 3600

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


def _gather() -> tuple[list[str], list[str], str]:
    """Return (all_code_files, untracked_code_files, content_for_triage)."""
    rc, _ = _git("rev-parse", "--git-dir")
    if rc != 0:
        return [], [], ""

    rc, mod = _git("diff", "HEAD", "--name-only")
    modified = [f for f in mod.splitlines() if Path(f).suffix in CODE_EXT]

    rc, unt = _git("ls-files", "--others", "--exclude-standard")
    untracked = [f for f in unt.splitlines() if Path(f).suffix in CODE_EXT]

    files = modified + untracked
    if not files:
        return [], [], ""

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

    return files, untracked, "\n".join(chunks)


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


def _load_state() -> dict:
    try:
        return json.loads(STATE_PATH.read_text())
    except (OSError, ValueError):
        return {}


def _save_state(state: dict) -> None:
    try:
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        STATE_PATH.write_text(json.dumps(state))
    except OSError:
        pass


def _already_reviewed(state: dict, content_hash: str) -> bool:
    """True if this exact diff was reviewed within STATE_TTL_SECONDS."""
    entry = state.get(content_hash)
    if not isinstance(entry, (int, float)):
        return False
    return (time.time() - entry) < STATE_TTL_SECONDS


def _record_review(state: dict, content_hash: str) -> None:
    now = time.time()
    state[content_hash] = now
    # Prune anything older than the TTL so the file stays tiny.
    expired = [k for k, ts in state.items()
               if not isinstance(ts, (int, float)) or now - ts >= STATE_TTL_SECONDS]
    for k in expired:
        state.pop(k, None)
    _save_state(state)


def main() -> int:
    triage_only = "--triage-only" in sys.argv

    if not PROJECT_DIR.is_dir():
        return 0
    if not triage_only and not ACTION.exists():
        return 0

    # Single-flight: if another auto-review.py is mid-run for this project,
    # skip this fire entirely. Stale-by-one is fine — the next user turn
    # will fire a fresh review against the latest state. Without this lock,
    # rapid turn ends stack concurrent claude -p chains that compete for
    # the same API quota and never produce a wake-up.
    #
    # Lock release rules (belt and suspenders):
    #   - Normal return / exception: the finally block calls LOCK_UN + close
    #   - Process crash / SIGKILL: the kernel closes FDs during teardown,
    #     which releases the flock automatically
    #   - Reboot: in-memory lock table is gone; lock file on disk is harmless
    try:
        LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
        lock_fd = open(LOCK_PATH, "w")
    except OSError:
        return 0
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock_fd.close()
        return 0
    try:
        return _main_locked(triage_only)
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        lock_fd.close()


def _main_locked(triage_only: bool) -> int:
    files, untracked, content = _gather()
    if not files or not content.strip():
        return 0

    # Diff-state cache: skip if we already reviewed this exact content
    # within the TTL window. Hash includes both file content and the
    # ordered file list to defeat false-positive cache hits.
    state = _load_state()
    content_hash = hashlib.sha256(
        ("\n".join(sorted(files)) + "\n---\n" + content).encode()
    ).hexdigest()
    if _already_reviewed(state, content_hash):
        return 0

    if not _triage(content):
        _record_review(state, content_hash)
        return 0

    if triage_only:
        print("triage: YES", file=sys.stderr)
        return 2

    # Pass the file list we captured in _gather() rather than letting
    # security-review-action.py recompute via `git diff HEAD` — the diff
    # excludes untracked files, and the working tree can change while the
    # async hook is in flight. The list is a snapshot of what was present
    # when the hook fired.
    cmd = [
        sys.executable,
        str(ACTION),
        "--repo-dir",
        str(PROJECT_DIR),
        "--files",
        *files,
        "--model",
        "haiku",
        "--timeout",
        "180",
        # We already verified the CLI works via the triage call above.
        # security-review-action.py's 30s preflight is shorter than the
        # plugin-load cold-start, so it false-fails in fully-plugged
        # sessions and silently exits the entire chain.
        "--no-preflight",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    out = proc.stdout or ""

    # Whatever the review concluded, mark this content as reviewed so a
    # repeat fire on the same diff (rapid turn ends with no new edits)
    # doesn't burn another pr-review cycle.
    _record_review(state, content_hash)

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
