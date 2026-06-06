#!/usr/bin/env python3
"""
Soundcheck auto-review — Stop hook driver.

Fires after Claude finishes a turn. Three stages before surfacing
findings to Claude:

  1. Local file-extension gate (~10ms): only proceed if at least one
     code-file has changed since the session baseline.

  2. Haiku triage (~3s warm, ~30s+ cold start, ~$0.003 per call):
     one short claude -p call asking "does this diff need a security
     review?". The cost and latency come from claude -p loading every
     enabled plugin's system prompt (~30K cached tokens) on each
     invocation. Skips silently on NO or parse failure. No timeout —
     the script runs detached via asyncRewake, so a slow triage cannot
     block the user.

  3. Full pr-review (~30-60s on haiku): on triage YES, spawn
     security-review-action.py against the changed file list, surface
     findings to stderr, exit 2 (asyncRewake → wakes Claude).

Scope of "changed": files modified, added, or committed during the
session, plus any currently untracked code files. The script reads the
hook event JSON on stdin to get the Claude Code session_id, snapshots
HEAD on first fire into ``$CLAUDE_PLUGIN_DATA/auto-review-session-
<id>.json``, and diffs every subsequent fire against that baseline.
This catches changes Claude has already committed during the session —
``git diff HEAD`` alone would miss them. Falls back to ``HEAD`` diff
when no session id is available (CLI runs, tests).

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
import re
import subprocess
import sys
import time
from pathlib import Path

# git's hardcoded empty-tree SHA. Fallback baseline when the repo has no
# commits yet (rare but possible when Claude is bootstrapping a new project).
# Diffing against this lists every file in the working tree.
_EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
_SESSION_STATE_TTL_SECONDS = 30 * 24 * 3600


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


def _read_hook_event() -> dict:
    """Read the hook event JSON Claude Code pipes to subprocess stdin.

    Returns ``{}`` when stdin is a tty (script run by hand), empty, or
    unparseable — all callers treat absence as "no session info."
    """
    if sys.stdin.isatty():
        return {}
    try:
        data = sys.stdin.read()
    except OSError:
        return {}
    if not data:
        return {}
    try:
        return json.loads(data)
    except (json.JSONDecodeError, ValueError):
        return {}


def _session_id_from(event: dict) -> str | None:
    """Return a filesystem-safe session id, or None when no session is known."""
    sid = event.get("session_id") or os.environ.get("CLAUDE_CODE_REMOTE_SESSION_ID")
    if not sid:
        return None
    # Sanitize before using as a filename. CC session_ids are UUIDs in
    # practice but nothing in the hook protocol guarantees it.
    sid = re.sub(r"[^A-Za-z0-9._-]", "_", str(sid))[:128]
    return sid or None


def _session_state_path(session_id: str) -> Path:
    return _STATE_BASE / f"auto-review-session-{session_id}.json"


def _touched_paths_file(session_id: str) -> Path:
    # Keyed by session AND project so concurrent Claude Code instances using
    # the same session_id (resume / split window / continued session) in
    # different repos don't stomp on each other's lists. v1.13.1 keyed by
    # session only and cross-project writes corrupted the file.
    return _STATE_BASE / f"auto-review-touched-{session_id}-{_PROJECT_KEY}.json"


LOG_PATH = _STATE_BASE / "auto-review.log"


def _log(stage: str, **kwargs) -> None:
    """Append one JSON line per fire. Silent on failure (logging must not
    block the actual review). Read with ``tail -f`` or ``jq``."""
    entry = {"ts": round(time.time(), 3), "stage": stage, **kwargs}
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_PATH, "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


def _consume_touched_paths(session_id: str | None) -> list[str]:
    """Atomically read + clear the PostToolUse-recorded path list.

    Returns the paths Claude touched since the last consume — typically
    the files edited during the just-finished turn. Returns [] if no
    list exists, the session id is absent, or any IO fails. The Stop
    hook intersects this with the baseline diff to restrict review
    scope; an empty list means "fall back to the full baseline scope."
    """
    if not session_id:
        return []
    target = _touched_paths_file(session_id)
    try:
        with open(target, "r+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            raw = f.read()
            try:
                paths = json.loads(raw) if raw else []
            except (json.JSONDecodeError, ValueError):
                paths = []
            if not isinstance(paths, list):
                paths = []
            f.seek(0)
            f.truncate()
            f.write("[]")
    except OSError:
        return []
    return [p for p in paths if isinstance(p, str) and p]


# Stripping every per-language comment exactly is overkill for a triage
# pre-filter. We just want to recognize "the diff is *only* trivia, no
# real code." So we strip the common single-line comment forms and any
# /* */ or <!-- --> block, then check whether anything non-whitespace
# remains. False negatives (we miss a comment form) just cost the LLM
# call we would have made anyway.
_COMMENT_BLOCK_RE = re.compile(r"/\*.*?\*/|<!--.*?-->", re.DOTALL)
_COMMENT_LINE_RE = re.compile(
    r"^\s*(#|//|--|;{1,2}|%{1,2}|'{1,3})"
)


def _is_trivial_diff(content: str) -> bool:
    """True if the gathered content is only whitespace + comments.

    Cheap pre-stage filter so we don't burn a haiku triage on a turn
    that only reformatted code or added a docstring.
    """
    if not content.strip():
        return True
    stripped = _COMMENT_BLOCK_RE.sub("", content)
    for ln in stripped.splitlines():
        if not ln.strip():
            continue
        if _COMMENT_LINE_RE.match(ln):
            continue
        return False
    return True


def _gc_old_session_state() -> None:
    """Best-effort sweep of stale per-session files. Called on new session init."""
    if not _STATE_BASE.is_dir():
        return
    cutoff = time.time() - _SESSION_STATE_TTL_SECONDS
    try:
        for p in _STATE_BASE.glob("auto-review-session-*.json"):
            try:
                if p.stat().st_mtime < cutoff:
                    p.unlink()
            except OSError:
                continue
    except OSError:
        return


def _baseline_sha(session_id: str | None) -> str | None:
    """Return the baseline SHA for ``session_id``, initializing on first use.

    First fire in a session snapshots the current HEAD and persists it.
    Subsequent fires diff against that same SHA so commits made *during*
    the session stay in scope until the session ends. Returns ``None`` when
    no session id is available (e.g. ad-hoc CLI run); callers fall back to
    diffing against ``HEAD``.
    """
    if not session_id:
        return None
    p = _session_state_path(session_id)
    try:
        existing = json.loads(p.read_text())
        sha = existing.get("baseline_sha")
        if isinstance(sha, str) and sha:
            return sha
    except (OSError, ValueError):
        pass
    rc, head = _git("rev-parse", "HEAD")
    sha = head.strip() if rc == 0 and head.strip() else _EMPTY_TREE_SHA
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"baseline_sha": sha, "first_seen_ts": time.time()}))
    except OSError:
        # State write failed but the in-memory SHA still works for this fire;
        # next fire will simply re-snapshot HEAD if state is still unwritable.
        pass
    _gc_old_session_state()
    return sha


def _gather(baseline: str | None, scope: list[str] | None = None) -> tuple[list[str], list[str], str]:
    """Return (all_code_files, untracked_code_files, content_for_triage).

    ``baseline`` is the diff base (typically the session-start SHA). When
    ``None``, falls back to ``HEAD`` so the script still works for ad-hoc
    CLI invocations outside a Claude Code hook context.

    ``scope`` is the optional PostToolUse-recorded list of files Claude
    actually touched this turn. When non-empty, we intersect the
    baseline-derived modified set + untracked set with it so we only
    review what just changed instead of everything since session start.
    """
    rc, _ = _git("rev-parse", "--git-dir")
    if rc != 0:
        return [], [], ""

    base = baseline or "HEAD"
    # --diff-filter=ACMR matches the filter security-review-action.py applies
    # via get_changed_files; D (deleted) is excluded since there's no file
    # to read.
    rc, mod = _git("diff", "--name-only", "--diff-filter=ACMR", base)
    if rc != 0 and baseline and baseline != "HEAD":
        # Baseline SHA may have been rewritten (rebase/reset). Fall back to
        # HEAD so the hook still produces something this fire; the next
        # session-init will re-snapshot.
        rc, mod = _git("diff", "--name-only", "--diff-filter=ACMR", "HEAD")
    modified = [
        f for f in mod.splitlines()
        if Path(f).suffix in CODE_EXT and (PROJECT_DIR / f).is_file()
    ]

    rc, unt = _git("ls-files", "--others", "--exclude-standard")
    untracked = [f for f in unt.splitlines() if Path(f).suffix in CODE_EXT]

    files = modified + untracked
    if scope:
        scope_set = set(scope)
        files = [f for f in files if f in scope_set]
        untracked = [f for f in untracked if f in scope_set]
    if not files:
        return [], [], ""

    # Read each file's current on-disk content. With a session baseline, the
    # "modified" set may include files committed during the session; their
    # current content is what we want to triage on, not the incremental diff.
    chunks: list[str] = []
    for f in files:
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
        _log("skip_lock_open_failed")
        return 0
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock_fd.close()
        _log("skip_locked")
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
    t_start = time.time()
    # Per-session baseline lets us include changes Claude has already
    # committed during this session, not just uncommitted ones. Falls
    # back to HEAD diff when no session id is available (CLI run, test
    # harness). See docs/auto-review-postmortem.md "v1.13 architecture".
    session_id = _session_id_from(_read_hook_event())
    sid_short = (session_id or "")[:8]
    baseline = _baseline_sha(session_id)
    # PostToolUse records every Edit/Write/MultiEdit/NotebookEdit path
    # during the turn; consuming the list scopes review to this turn's
    # touches instead of the full baseline..HEAD set. Empty list falls
    # back to the wider scope (correct for CLI runs and the very first
    # fire of a session before any tool has run).
    touched = _consume_touched_paths(session_id)
    files, untracked, content = _gather(baseline, scope=touched or None)
    if not files or not content.strip():
        _log("skip_no_files", session=sid_short, touched=len(touched))
        return 0

    # Free pre-triage filter: if the diff is only whitespace + comments,
    # skip the LLM call entirely. Common after a reformat or doc-only turn.
    if _is_trivial_diff(content):
        _log("skip_trivial", session=sid_short, files=len(files))
        return 0

    # Diff-state cache: skip if we already reviewed this exact content
    # within the TTL window. Hash includes both file content and the
    # ordered file list to defeat false-positive cache hits.
    state = _load_state()
    content_hash = hashlib.sha256(
        ("\n".join(sorted(files)) + "\n---\n" + content).encode()
    ).hexdigest()
    if _already_reviewed(state, content_hash):
        _log("skip_cache_hit", session=sid_short, files=len(files))
        return 0

    if not _triage(content):
        _record_review(state, content_hash)
        _log("skip_triage_no", session=sid_short, files=len(files),
             wall_s=round(time.time() - t_start, 1))
        return 0

    if triage_only:
        print("triage: YES", file=sys.stderr)
        _log("triage_only_yes", session=sid_short, files=len(files),
             wall_s=round(time.time() - t_start, 1))
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

    # security-review-action.py's documented exit-code contract:
    #   0 = clean (no Critical/High findings)
    #   1 = Critical/High findings present
    #   2 = infrastructure error
    # Trust the exit code rather than scraping the stdout for a
    # `<soundcheck-findings>` tag — current pr-review output is a
    # human-readable Markdown table without that machine-readable block.
    if proc.returncode != 1:
        _log("clean" if proc.returncode == 0 else "review_error",
             session=sid_short, files=len(files), pr_rc=proc.returncode,
             wall_s=round(time.time() - t_start, 1))
        return 0

    _log("findings", session=sid_short, files=len(files),
         wall_s=round(time.time() - t_start, 1))
    print(
        "Soundcheck auto-review found issues in your recent edits. "
        "Address each finding or push back with a concrete reason.\n",
        file=sys.stderr,
    )
    print(out, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
