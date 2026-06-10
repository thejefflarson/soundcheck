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

# Per-repo state directory under CLAUDE_PLUGIN_DATA (the docs-guaranteed
# persistent location). Falls back to /tmp if the env var is missing.
_STATE_BASE = Path(
    os.environ.get("CLAUDE_PLUGIN_DATA")
    or os.environ.get("TMPDIR", "/tmp")
)
STATE_TTL_SECONDS = 24 * 3600


def _repo_key(repo_root: Path) -> str:
    return hashlib.sha256(str(Path(repo_root).resolve()).encode()).hexdigest()[:16]


def _lock_path(repo_key: str) -> Path:
    return _STATE_BASE / f"auto-review-{repo_key}.lock"


def _state_path(repo_key: str) -> Path:
    return _STATE_BASE / f"auto-review-{repo_key}.state.json"

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

def _git(*args: str, cwd: Path | None = None) -> tuple[int, str]:
    r = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        cwd=cwd or PROJECT_DIR,
    )
    return r.returncode, r.stdout


def _resolve_repo_root(path: str) -> Path | None:
    """Return the top-level git repo containing ``path``, or None if not in one.

    ``path`` may be relative (project-relative, recorded by older versions
    of record-touched-path.py) or absolute (the new cross-repo recording).
    Relative paths are resolved against PROJECT_DIR. Returns None for
    paths that are outside any git working tree.
    """
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = PROJECT_DIR / candidate
    try:
        candidate = candidate.resolve()
    except OSError:
        return None
    # git rev-parse --show-toplevel works from any subdir; if the path is a
    # file, walk up to its parent dir for the cwd.
    cwd = candidate if candidate.is_dir() else candidate.parent
    if not cwd.exists():
        return None
    rc, out = _git("rev-parse", "--show-toplevel", cwd=cwd)
    if rc != 0:
        return None
    out = out.strip()
    if not out:
        return None
    return Path(out)


def _bucket_paths_by_repo(touched: list[str]) -> tuple[dict[Path, list[str]], int]:
    """Group ``touched`` paths by their containing git repo.

    Returns ``(buckets, orphans)`` where ``buckets`` maps each repo root to
    the list of paths inside it (relative to that repo root) and ``orphans``
    is the count of paths not in any git working tree.
    """
    buckets: dict[Path, list[str]] = {}
    orphans = 0
    for p in touched:
        repo = _resolve_repo_root(p)
        if repo is None:
            orphans += 1
            continue
        abs_p = (PROJECT_DIR / p).resolve() if not Path(p).is_absolute() else Path(p).resolve()
        try:
            rel = str(abs_p.relative_to(repo))
        except ValueError:
            orphans += 1
            continue
        buckets.setdefault(repo, []).append(rel)
    return buckets, orphans


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


def _session_state_path(session_id: str, repo_key: str) -> Path:
    # Per-session AND per-repo. A single session refactoring across two
    # repos has a distinct baseline SHA in each — they're different working
    # states. Pre-v1.14 files (auto-review-session-{sid}.json with no
    # repo_key) are ignored; the next fire re-snapshots HEAD for each repo.
    return _STATE_BASE / f"auto-review-session-{session_id}-{repo_key}.json"


def _touched_paths_file(session_id: str) -> Path:
    # Keyed by session AND launching project (CLAUDE_PROJECT_DIR) so
    # concurrent Claude Code instances using the same session_id (resume /
    # split window / continued session) in different launching projects
    # don't stomp on each other's lists. The list itself may contain paths
    # in OTHER repos (cross-repo refactor) — auto-review.py buckets by
    # actual containing git repo when consuming.
    return (_STATE_BASE
            / f"auto-review-touched-{session_id}-{_repo_key(PROJECT_DIR)}.json")


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


def _baseline_sha(session_id: str | None, repo_root: Path, repo_key: str) -> str | None:
    """Return the baseline SHA for ``(session_id, repo_root)``, init on first use.

    First fire in this (session, repo) pair snapshots HEAD and persists it.
    Subsequent fires diff against that same SHA so commits made *during*
    the session stay in scope. Returns ``None`` when no session id is
    available (e.g. ad-hoc CLI run); callers fall back to diffing against
    ``HEAD``.
    """
    if not session_id:
        return None
    p = _session_state_path(session_id, repo_key)
    try:
        existing = json.loads(p.read_text())
        sha = existing.get("baseline_sha")
        if isinstance(sha, str) and sha:
            return sha
    except (OSError, ValueError):
        pass
    rc, head = _git("rev-parse", "HEAD", cwd=repo_root)
    sha = head.strip() if rc == 0 and head.strip() else _EMPTY_TREE_SHA
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"baseline_sha": sha, "first_seen_ts": time.time()}))
    except OSError:
        pass
    _gc_old_session_state()
    return sha


def _gather(repo_root: Path, baseline: str | None, scope: list[str] | None = None
            ) -> tuple[list[str], list[str], str]:
    """Return (all_code_files, untracked_code_files, content_for_triage).

    Operates against ``repo_root`` (the repo containing the touched files,
    which may differ from ``PROJECT_DIR`` in multi-repo refactors).
    """
    rc, _ = _git("rev-parse", "--git-dir", cwd=repo_root)
    if rc != 0:
        return [], [], ""

    base = baseline or "HEAD"
    rc, mod = _git("diff", "--name-only", "--diff-filter=ACMR", base, cwd=repo_root)
    if rc != 0 and baseline and baseline != "HEAD":
        rc, mod = _git("diff", "--name-only", "--diff-filter=ACMR", "HEAD", cwd=repo_root)
    modified = [
        f for f in mod.splitlines()
        if Path(f).suffix in CODE_EXT and (repo_root / f).is_file()
    ]

    rc, unt = _git("ls-files", "--others", "--exclude-standard", cwd=repo_root)
    untracked = [f for f in unt.splitlines() if Path(f).suffix in CODE_EXT]

    files = modified + untracked
    if scope:
        scope_set = set(scope)
        files = [f for f in files if f in scope_set]
        untracked = [f for f in untracked if f in scope_set]
    if not files:
        return [], [], ""

    chunks: list[str] = []
    for f in files:
        try:
            chunks.append((repo_root / f).read_text(errors="replace"))
        except OSError:
            pass

    return files, untracked, "\n".join(chunks)


def _triage(content: str) -> tuple[bool, str]:
    """One-shot haiku call: does this diff plausibly need a security review?

    Returns ``(answered_yes, diag)`` where ``diag`` summarizes any failure
    (rc, stderr tail) for the observability log. Empty diag on success.

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
        return False, "claude CLI not on PATH"
    if r.returncode != 0:
        tail = (r.stderr or r.stdout or "").strip()[-200:]
        return False, f"rc={r.returncode}: {tail!r}"
    if not r.stdout:
        return False, "empty stdout"
    first = r.stdout.strip().splitlines()[0].strip().upper() if r.stdout.strip() else ""
    return first.startswith("YES"), ""


def _load_state(repo_key: str) -> dict:
    try:
        return json.loads(_state_path(repo_key).read_text())
    except (OSError, ValueError):
        return {}


def _save_state(repo_key: str, state: dict) -> None:
    p = _state_path(repo_key)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(state))
    except OSError:
        pass


def _already_reviewed(state: dict, content_hash: str) -> bool:
    """True if this exact diff was reviewed within STATE_TTL_SECONDS."""
    entry = state.get(content_hash)
    if not isinstance(entry, (int, float)):
        return False
    return (time.time() - entry) < STATE_TTL_SECONDS


def _record_review(repo_key: str, state: dict, content_hash: str) -> None:
    now = time.time()
    state[content_hash] = now
    expired = [k for k, ts in state.items()
               if not isinstance(ts, (int, float)) or now - ts >= STATE_TTL_SECONDS]
    for k in expired:
        state.pop(k, None)
    _save_state(repo_key, state)


def main() -> int:
    triage_only = "--triage-only" in sys.argv

    if not PROJECT_DIR.is_dir():
        return 0
    if not triage_only and not ACTION.exists():
        return 0

    session_id = _session_id_from(_read_hook_event())
    sid_short = (session_id or "")[:8]

    # Bucket touched paths by their containing git repo. Cross-repo
    # refactors (e.g. app code + IaC) need each repo reviewed in its own
    # working tree with its own baseline. Empty touched list falls back
    # to single-bucket review of PROJECT_DIR for back-compat with CLI runs
    # and the very first fire of a session.
    touched = _consume_touched_paths(session_id)
    buckets, orphans = _bucket_paths_by_repo(touched) if touched else ({}, 0)
    if orphans:
        _log("skip_outside_repo", session=sid_short, count=orphans)
    if not buckets:
        # No touched-paths info → single-bucket review of the launching
        # project. Use [] (not None) for scope so _gather() doesn't filter,
        # since we have no positive list to intersect against.
        buckets = {PROJECT_DIR: []}

    overall_rc = 0
    combined_stderr_parts: list[str] = []
    for repo_root, scope in buckets.items():
        rc, table = _review_one_repo(
            repo_root, session_id, sid_short, scope, triage_only,
        )
        if rc == 2 and table:
            combined_stderr_parts.append(
                f"### Findings in `{repo_root}`\n\n{table}"
            )
            overall_rc = 2

    if overall_rc == 2 and combined_stderr_parts:
        print(
            "Soundcheck auto-review found issues in your recent edits. "
            "Address each finding or push back with a concrete reason.\n",
            file=sys.stderr,
        )
        for part in combined_stderr_parts:
            print(part, file=sys.stderr)
            print("", file=sys.stderr)
    return overall_rc


def _review_one_repo(repo_root: Path, session_id: str | None, sid_short: str,
                     scope: list[str], triage_only: bool) -> tuple[int, str]:
    """Per-(session, repo) review pipeline.

    Returns ``(rc, findings_table)``. ``rc`` is 0 (skipped, clean, error,
    or triage-only YES) or 2 (findings to surface). ``findings_table`` is
    the pr-review Markdown output to include in the asyncRewake wake-up,
    or empty when no findings.
    """
    repo_key = _repo_key(repo_root)
    repo_short = repo_key[:8]

    # Per-repo single-flight lock. Two repos can review in parallel.
    lock_path = _lock_path(repo_key)
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_fd = open(lock_path, "w")
    except OSError:
        _log("skip_lock_open_failed", session=sid_short, repo=repo_short)
        return 0, ""
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock_fd.close()
        _log("skip_locked", session=sid_short, repo=repo_short)
        return 0, ""

    try:
        return _review_one_repo_locked(
            repo_root, repo_key, repo_short, session_id, sid_short,
            scope, triage_only,
        )
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        lock_fd.close()


def _review_one_repo_locked(repo_root: Path, repo_key: str, repo_short: str,
                            session_id: str | None, sid_short: str,
                            scope: list[str], triage_only: bool) -> tuple[int, str]:
    t_start = time.time()
    baseline = _baseline_sha(session_id, repo_root, repo_key)
    files, untracked, content = _gather(repo_root, baseline,
                                        scope=scope or None)
    if not files or not content.strip():
        _log("skip_no_files", session=sid_short, repo=repo_short,
             touched=len(scope))
        return 0, ""

    if _is_trivial_diff(content):
        _log("skip_trivial", session=sid_short, repo=repo_short,
             files=len(files))
        return 0, ""

    state = _load_state(repo_key)
    content_hash = hashlib.sha256(
        ("\n".join(sorted(files)) + "\n---\n" + content).encode()
    ).hexdigest()
    if _already_reviewed(state, content_hash):
        _log("skip_cache_hit", session=sid_short, repo=repo_short,
             files=len(files))
        return 0, ""

    triage_yes, triage_diag = _triage(content)
    if not triage_yes:
        _record_review(repo_key, state, content_hash)
        _log("skip_triage_no", session=sid_short, repo=repo_short,
             files=len(files), wall_s=round(time.time() - t_start, 1),
             **({"diag": triage_diag} if triage_diag else {}))
        return 0, ""

    if triage_only:
        _log("triage_only_yes", session=sid_short, repo=repo_short,
             files=len(files), wall_s=round(time.time() - t_start, 1))
        return 2, "triage: YES"

    cmd = [
        sys.executable,
        str(ACTION),
        "--repo-dir",
        str(repo_root),
        "--files",
        *files,
        "--model",
        "haiku",
        "--timeout",
        "180",
        "--no-preflight",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    out = proc.stdout or ""
    _record_review(repo_key, state, content_hash)

    if proc.returncode != 1:
        _log("clean" if proc.returncode == 0 else "review_error",
             session=sid_short, repo=repo_short, files=len(files),
             pr_rc=proc.returncode,
             wall_s=round(time.time() - t_start, 1))
        return 0, ""

    _log("findings", session=sid_short, repo=repo_short, files=len(files),
         wall_s=round(time.time() - t_start, 1))
    return 2, out


if __name__ == "__main__":
    sys.exit(main())
