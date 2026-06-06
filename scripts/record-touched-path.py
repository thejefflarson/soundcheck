#!/usr/bin/env python3
"""PostToolUse hook: record the file path Claude just edited.

Fires after every Edit / Write / MultiEdit / NotebookEdit. Appends the
edited path to a per-session list under ``$CLAUDE_PLUGIN_DATA``. The
Stop-hook driver (``auto-review.py``) atomically reads and clears the
list to restrict review scope to "files Claude actually touched this
turn" instead of "every file changed since the session baseline."

Synchronous hook — kept tiny (no LLM, no git) so it doesn't perceptibly
delay tool result delivery. Failures exit 0; missing data is harmless,
the Stop hook just falls back to the wider baseline scope.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import sys
from pathlib import Path

MAX_PATHS = 200


def _opted_out(v: str | None) -> bool:
    return (v or "").strip().lower() in ("0", "false", "no", "off")


if _opted_out(os.environ.get("SOUNDCHECK_AUTO_REVIEW")):
    sys.exit(0)


def _read_event() -> dict:
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


def _session_id(event: dict) -> str | None:
    sid = event.get("session_id") or os.environ.get("CLAUDE_CODE_REMOTE_SESSION_ID")
    if not sid:
        return None
    sid = re.sub(r"[^A-Za-z0-9._-]", "_", str(sid))[:128]
    return sid or None


def _file_path(event: dict) -> str | None:
    """Extract the edited file path from the tool input. Returns None for
    tools we don't track or events with no recognizable path field."""
    tool_input = event.get("tool_input") or {}
    # Edit / Write / MultiEdit all have file_path; NotebookEdit uses notebook_path.
    for key in ("file_path", "notebook_path"):
        v = tool_input.get(key)
        if isinstance(v, str) and v:
            return v
    return None


def _state_dir() -> Path:
    return Path(os.environ.get("CLAUDE_PLUGIN_DATA")
                or os.environ.get("TMPDIR", "/tmp"))


def _touched_paths_file(session_id: str, project_dir: Path) -> Path:
    # Must match the naming convention in auto-review.py._touched_paths_file().
    # Keyed by (session, project) so concurrent Claude Code instances sharing
    # a session_id across different repos don't stomp on each other's lists.
    project_key = hashlib.sha256(str(project_dir).encode()).hexdigest()[:16]
    return _state_dir() / f"auto-review-touched-{session_id}-{project_key}.json"


def main() -> int:
    event = _read_event()
    sid = _session_id(event)
    path = _file_path(event)
    if not sid or not path:
        return 0

    state_dir = _state_dir()
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return 0

    project_dir = Path(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()).resolve()
    target = _touched_paths_file(sid, project_dir)

    # Normalize to a project-relative path when possible — the Stop hook
    # consumes these as relative paths to match `git ls-files` / `git diff`
    # output. Paths outside the project are recorded verbatim; the Stop
    # hook filters them out.
    try:
        rel = str(Path(path).resolve().relative_to(project_dir))
    except (OSError, ValueError):
        rel = path

    # Acquire an exclusive lock for read-modify-write. fcntl.flock auto-
    # releases when the FD closes, so even a crash mid-write doesn't leak.
    try:
        with open(target, "a+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.seek(0)
            raw = f.read()
            try:
                paths = json.loads(raw) if raw else []
            except (json.JSONDecodeError, ValueError):
                paths = []
            if not isinstance(paths, list):
                paths = []
            if rel in paths:
                # Already known — move to the end so the dedup keeps the
                # most recent N. Cheap on a 200-cap list.
                paths.remove(rel)
            paths.append(rel)
            if len(paths) > MAX_PATHS:
                paths = paths[-MAX_PATHS:]
            f.seek(0)
            f.truncate()
            f.write(json.dumps(paths))
    except OSError:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
