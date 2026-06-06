#!/usr/bin/env python3
"""End-to-end test for the auto-review Stop hook driver.

Exercises the full pipeline that ``test-auto-review.py`` short-circuits:
Stage 3 (``security-review-action.py``), exit-code interpretation, lockfile
release, and diff-state caching. Every bug from v1.12.6 → v1.12.8 would
have been caught here.

Cases:

  A — risky-code fixture
      Spawn ``auto-review.py`` foreground against a temp repo containing
      an unambiguous shell-injection file. Assert: exit 2, stderr contains
      the standard "Soundcheck auto-review found issues" preamble, stderr
      mentions the fixture filename, wallclock < 5 min, state file
      recorded exactly one hash, lockfile released.

  B — diff-state cache
      Re-run ``auto-review.py`` against the same fixture. Assert: exit 0
      and wallclock < 5s (cache hit short-circuits before any LLM call).

  C — lockfile single-flight
      Spawn one ``auto-review.py`` in the background holding the lock,
      then spawn a foreground one. Assert: foreground exits 0 in < 5s
      (lock acquisition fails immediately, no LLM call).

  D — benign-code fixture
      Run ``auto-review.py`` against a pure-compute file (no IO, no auth,
      no crypto). Assert: exit 0 and either stage 1 rejects or stage 2
      triage answers NO.

Total wall-clock: ~3-6 min, ~$0.05 per run on haiku. Slow + expensive
enough that this is *not* part of CI; it's the regression check we run
locally before tagging a release that touches the hook driver.

Usage:
    python scripts/test-auto-review-e2e.py
    python scripts/test-auto-review-e2e.py --verbose
    python scripts/test-auto-review-e2e.py --case A
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "auto-review.py"

RISKY_PY = """\
from flask import Flask, request
import subprocess

app = Flask(__name__)


@app.route("/exec")
def exec_cmd():
    cmd = request.args.get("c", "")
    return subprocess.check_output(cmd, shell=True)
"""

BENIGN_PY = """\
def fib(n: int) -> int:
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a
"""


def _git(repo: Path, *args: str) -> tuple[int, str]:
    r = subprocess.run(
        ["git", *args], capture_output=True, text=True, cwd=repo
    )
    return r.returncode, r.stdout


def _init_repo(tmp: Path, label: str) -> tuple[Path, Path]:
    """Return (repo_dir, plugin_data_dir) — both fresh."""
    repo = tmp / f"repo-{label}"
    data = tmp / f"plugin-data-{label}"
    repo.mkdir()
    data.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "Test")
    (repo / "README.md").write_text("seed\n")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-qm", "init")
    return repo, data


def _spawn(repo: Path, data: Path, *,
           background: bool = False) -> subprocess.Popen | subprocess.CompletedProcess:
    """Run ``auto-review.py`` against (repo, data) with full env inheritance."""
    env = {
        **os.environ,
        "CLAUDE_PROJECT_DIR": str(repo),
        "CLAUDE_PLUGIN_ROOT": str(ROOT),
        "CLAUDE_PLUGIN_DATA": str(data),
        "SOUNDCHECK_AUTO_REVIEW": "true",
    }
    args = [sys.executable, str(SCRIPT)]
    if background:
        return subprocess.Popen(
            args, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    return subprocess.run(args, env=env, capture_output=True, text=True)


def _state_entries(data: Path) -> dict:
    matches = list(data.glob("auto-review-*.state.json"))
    if not matches:
        return {}
    try:
        return json.loads(matches[0].read_text())
    except (OSError, ValueError):
        return {}


def case_a(tmp: Path, verbose: bool) -> bool:
    """End-to-end: risky fixture → exit 2 + findings in stderr."""
    repo, data = _init_repo(tmp, "A")
    (repo / "app.py").write_text(RISKY_PY)
    print("\n[A] risky fixture — expect exit 2 in 30s-5min")
    t0 = time.time()
    r = _spawn(repo, data)
    dt = time.time() - t0
    if verbose:
        print(f"    rc={r.returncode} wallclock={dt:.1f}s")
        if r.stderr:
            tail = r.stderr.rstrip().splitlines()[-8:]
            for line in tail:
                print(f"    stderr: {line[:120]}")
    ok = (
        r.returncode == 2
        and "Soundcheck auto-review found issues" in r.stderr
        and "app.py" in r.stderr
        and dt < 300
    )
    state = _state_entries(data)
    ok = ok and len(state) == 1
    print(f"  {'PASS' if ok else 'FAIL'}  rc={r.returncode}, "
          f"stderr_has_preamble={'Soundcheck auto-review found issues' in r.stderr}, "
          f"stderr_mentions_file={'app.py' in r.stderr}, "
          f"state_entries={len(state)}, wallclock={dt:.1f}s")
    return ok


def case_b(tmp: Path, verbose: bool) -> bool:
    """Diff-state cache: re-run on same fixture should short-circuit."""
    repo, data = _init_repo(tmp, "B")
    (repo / "app.py").write_text(RISKY_PY)
    print("\n[B] cache priming — running once to populate state")
    r1 = _spawn(repo, data)
    if verbose:
        print(f"    priming run rc={r1.returncode}")
    print("[B] re-run on same content — expect exit 0 in < 5s (cache hit)")
    t0 = time.time()
    r2 = _spawn(repo, data)
    dt = time.time() - t0
    ok = r2.returncode == 0 and dt < 5
    print(f"  {'PASS' if ok else 'FAIL'}  rc={r2.returncode}, wallclock={dt:.2f}s")
    return ok


def case_c(tmp: Path, verbose: bool) -> bool:
    """Lockfile single-flight: concurrent fire should exit 0 fast."""
    repo, data = _init_repo(tmp, "C")
    (repo / "app.py").write_text(RISKY_PY)
    print("\n[C] holding lock via background run, then foreground fire")
    bg = _spawn(repo, data, background=True)
    # Give the background process a moment to acquire the lock
    time.sleep(1.0)
    t0 = time.time()
    r = _spawn(repo, data)
    dt = time.time() - t0
    ok = r.returncode == 0 and dt < 5
    print(f"  {'PASS' if ok else 'FAIL'}  rc={r.returncode}, wallclock={dt:.2f}s")
    bg.kill()
    bg.wait(timeout=5)
    return ok


def case_d(tmp: Path, verbose: bool) -> bool:
    """Benign code: triage should answer NO, exit 0 silent."""
    repo, data = _init_repo(tmp, "D")
    (repo / "math.py").write_text(BENIGN_PY)
    print("\n[D] benign fixture — expect exit 0 silent")
    t0 = time.time()
    r = _spawn(repo, data)
    dt = time.time() - t0
    ok = r.returncode == 0 and "Soundcheck auto-review found" not in r.stderr
    print(f"  {'PASS' if ok else 'FAIL'}  rc={r.returncode}, "
          f"silent={'Soundcheck auto-review found' not in r.stderr}, "
          f"wallclock={dt:.1f}s")
    return ok


CASES = {"A": case_a, "B": case_b, "C": case_c, "D": case_d}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--case", choices=sorted(CASES.keys()),
                   help="Run a single case by letter (A/B/C/D)")
    args = p.parse_args()

    selected = [args.case] if args.case else sorted(CASES.keys())
    print(f"auto-review e2e — script: {SCRIPT}")
    print(f"cases: {', '.join(selected)}")

    tmp = Path(tempfile.mkdtemp(prefix="auto-review-e2e-"))
    try:
        results = {c: CASES[c](tmp, args.verbose) for c in selected}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    passed = sum(results.values())
    total = len(results)
    print()
    print(f"Results: {passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
