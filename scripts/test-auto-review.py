#!/usr/bin/env python3
"""Fixture-based test for the auto-review Stop hook driver.

Exercises the local file-extension gate and the haiku triage call on
representative diffs. The full pr-review stage (security-review-action.py)
is already covered by smoke-test-skills.py and benchmark-eval.py, so this
test uses ``--triage-only`` to short-circuit after the triage verdict.

Cases:

- Clean repo, no changes              → exit 0 silent
- Markdown-only change                → exit 0 silent (gate rejects)
- Benign code change                  → exit 0 silent (triage NO)
- Risky code change (subprocess + shell=True from user input)
                                       → exit 2 (triage YES)

Total wall-clock: ~10-15s, ~$0.005 per run on haiku.

Usage:
    python scripts/test-auto-review.py
    python scripts/test-auto-review.py --verbose

End-to-end (hook lifecycle) check — done by hand, ~2 min:

  1. In a throwaway repo, launch:
         claude --plugin-dir /path/to/soundcheck
  2. Inside Claude Code, run /plugin and confirm `autoReview` is on
     (default-true; flip explicitly with /plugin config soundcheck if
     it doesn't show).
  3. Ask Claude to write a small risky file, e.g. a Flask handler that
     shells out with subprocess.run(request.args[...], shell=True).
  4. After Claude finishes the turn, the Stop hook fires asynchronously.
     Within ~30-60s a system reminder should appear in Claude's next
     turn containing a soundcheck findings table.
  5. Disable with /plugin config soundcheck autoReview=false and repeat
     step 3 — no reminder should appear.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "auto-review.py"

BENIGN_PY = """\
def greet(name: str) -> str:
    return f"hello, {name}"
"""

RISKY_PY = """\
import subprocess
from flask import request, Flask

app = Flask(__name__)

@app.route("/run")
def run():
    cmd = request.args.get("cmd", "")
    return subprocess.check_output(cmd, shell=True)
"""


def _git(repo: Path, *args: str) -> tuple[int, str, str]:
    r = subprocess.run(
        ["git", *args], capture_output=True, text=True, cwd=repo
    )
    return r.returncode, r.stdout, r.stderr


def _init_repo() -> Path:
    repo = Path(tempfile.mkdtemp(prefix="auto-review-test-"))
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    (repo / "README.md").write_text("seed\n")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-qm", "init")
    return repo


def _run_hook(repo: Path, verbose: bool) -> int:
    import os as _os
    env = {
        **_os.environ,
        "CLAUDE_PROJECT_DIR": str(repo),
        "CLAUDE_PLUGIN_ROOT": str(ROOT),
        "SOUNDCHECK_AUTO_REVIEW": "true",
    }
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--triage-only"],
        env=env,
        capture_output=True,
        text=True,
    )
    if verbose:
        if r.stdout:
            print(f"    stdout: {r.stdout.rstrip()}")
        if r.stderr:
            print(f"    stderr: {r.stderr.rstrip()}")
    return r.returncode


def _case(name: str, expect: int, setup, verbose: bool) -> bool:
    repo = _init_repo()
    try:
        setup(repo)
        actual = _run_hook(repo, verbose)
        ok = actual == expect
        marker = "PASS" if ok else "FAIL"
        print(f"  {marker}  {name:40s} expect exit {expect}, got {actual}")
        return ok
    finally:
        shutil.rmtree(repo, ignore_errors=True)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    print(f"auto-review test — script: {SCRIPT}")
    print()

    cases = [
        ("clean repo, no changes", 0, lambda _r: None),
        (
            "markdown-only change",
            0,
            lambda r: (r / "notes.md").write_text("# notes\n"),
        ),
        (
            "benign code change",
            0,
            lambda r: (r / "greet.py").write_text(BENIGN_PY),
        ),
        (
            "risky code change",
            2,
            lambda r: (r / "app.py").write_text(RISKY_PY),
        ),
    ]

    results = [_case(name, expect, setup, args.verbose)
               for name, expect, setup in cases]
    passed = sum(results)
    total = len(results)

    print()
    print(f"Results: {passed}/{total} passed")
    if passed == total:
        print()
        print("End-to-end hook check — manual, ~2 min:")
        print("  claude --plugin-dir <soundcheck>  →  /plugin enable autoReview")
        print("  → ask Claude to write a risky handler → wait for the next-turn")
        print("    system reminder with the findings table.")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
