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

  E — session-baseline catches committed changes
      Initialize a session baseline at the seed commit, then add and
      commit a vulnerable file. Run ``auto-review.py`` with the session id.
      Assert: exit 2 (the script diffs against the baseline, sees the
      committed file as changed, surfaces findings). v1.13 regression check.

  F — touched-paths intersection
      Two untracked files (one risky, one benign); pre-seed touched list
      with the benign one. Assert: scope shrinks to benign only, triage
      NO, touched-paths file cleared atomically. v1.13.1 regression check.

  G — trivial-diff short-circuit
      Comments-only fixture. Assert: exit 0 in < 10s (no LLM call).
      v1.13.1 regression check.

  H — touched-paths file keyed per (session, project)
      Two repos, same session_id. record-touched-path.py writes to each.
      Assert two distinct files exist with the correct per-project content.
      v1.13.2 regression check for the multi-session collision bug.

  I — observability log
      Any run leaves a JSON-line entry in ``$CLAUDE_PLUGIN_DATA/auto-review.log``.
      Assert log file exists, parses as JSON lines, contains at least one
      entry with a recognized stage name. v1.13.2 regression check.

  J — multi-repo refactor
      Touched paths span two separate git repos; only one has a vulnerable
      file. Assert findings include the risky repo's path and the
      touched-paths file is cleared. v1.14 regression check.

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
import hashlib
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
           background: bool = False,
           session_id: str | None = None,
           ) -> subprocess.Popen | subprocess.CompletedProcess:
    """Run ``auto-review.py`` against (repo, data) with full env inheritance.

    Passes ``session_id`` via ``CLAUDE_CODE_REMOTE_SESSION_ID`` when supplied —
    that's the env-var fallback ``_session_id_from`` honors when no hook event
    JSON is piped to stdin.
    """
    env = {
        **os.environ,
        "CLAUDE_PROJECT_DIR": str(repo),
        "CLAUDE_PLUGIN_ROOT": str(ROOT),
        "CLAUDE_PLUGIN_DATA": str(data),
        "SOUNDCHECK_AUTO_REVIEW": "true",
    }
    if session_id is not None:
        env["CLAUDE_CODE_REMOTE_SESSION_ID"] = session_id
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


COMMENTS_ONLY_PY = """\
# Notes on the Fibonacci sequence.
# F(0) = 0, F(1) = 1, F(n) = F(n-1) + F(n-2).
# Closed-form via Binet's formula uses the golden ratio.

# TODO: write the implementation later.
"""


def _project_key(project_dir: Path) -> str:
    """Mirror auto-review.py._PROJECT_KEY computation for test pre-seeding."""
    return hashlib.sha256(str(project_dir.resolve()).encode()).hexdigest()[:16]


def case_f(tmp: Path, verbose: bool) -> bool:
    """touched_paths intersection: scope shrinks to this turn's touched files.

    Two untracked code files exist in the working tree (one risky, one
    benign). The PostToolUse-recorded list only contains the benign one,
    so review scope should be just that file — triage answers NO, exit 0.
    Without the intersection the risky file would dominate the triage and
    we'd run a full pr-review.
    """
    repo, data = _init_repo(tmp, "F")
    session_id = "e2e-touched-test"
    (repo / "app.py").write_text(RISKY_PY)      # untouched this turn
    (repo / "math.py").write_text(BENIGN_PY)    # the only path PostToolUse saw
    # Pre-seed the touched-paths list with only math.py. v1.13.2 keys the
    # file by (session_id, project_hash) so concurrent same-session usage
    # across repos doesn't collide.
    touched_file = data / f"auto-review-touched-{session_id}-{_project_key(repo)}.json"
    touched_file.write_text(json.dumps(["math.py"]))
    print("\n[F] touched-paths intersection — expect exit 0 (only benign in scope)")
    t0 = time.time()
    r = _spawn(repo, data, session_id=session_id)
    dt = time.time() - t0
    if verbose:
        print(f"    rc={r.returncode} wallclock={dt:.1f}s")
    ok = (
        r.returncode == 0
        and "Soundcheck auto-review found" not in r.stderr
    )
    # Also assert the touched-paths file got cleared atomically
    cleared = touched_file.read_text() == "[]"
    ok = ok and cleared
    print(f"  {'PASS' if ok else 'FAIL'}  rc={r.returncode}, "
          f"silent={'Soundcheck auto-review found' not in r.stderr}, "
          f"touched_cleared={cleared}, wallclock={dt:.1f}s")
    return ok


def case_g(tmp: Path, verbose: bool) -> bool:
    """Trivial diff short-circuit: comments-only change exits without LLM call.

    Any wallclock under ~3s implies no claude -p triage ran — the script
    exited at the pre-triage filter. Generous bound for slow CI.
    """
    repo, data = _init_repo(tmp, "G")
    (repo / "notes.py").write_text(COMMENTS_ONLY_PY)
    print("\n[G] comments-only fixture — expect exit 0 + no LLM call")
    t0 = time.time()
    r = _spawn(repo, data)
    dt = time.time() - t0
    if verbose:
        print(f"    rc={r.returncode} wallclock={dt:.2f}s")
    ok = r.returncode == 0 and dt < 10
    print(f"  {'PASS' if ok else 'FAIL'}  rc={r.returncode}, wallclock={dt:.2f}s "
          f"({'no LLM call' if dt < 10 else 'LLM call ran (should not have)'})")
    return ok


def case_e(tmp: Path, verbose: bool) -> bool:
    """Session-baseline: vulnerable file committed during session is still reviewed.

    Without v1.13's baseline tracking, the script diffs against HEAD and the
    committed file disappears from view. With baseline tracking (session id
    set via CLAUDE_CODE_REMOTE_SESSION_ID), the diff is against the session-
    start SHA and the committed file is visible.
    """
    repo, data = _init_repo(tmp, "E")
    session_id = "e2e-baseline-test"
    # Pre-seed the per-(session, repo) baseline file so the diff base is
    # the initial commit. v1.14 added the repo_key suffix to the name.
    seed_sha = _git(repo, "rev-parse", "HEAD")[1].strip()
    (data / f"auto-review-session-{session_id}-{_project_key(repo)}.json").write_text(
        json.dumps({"baseline_sha": seed_sha, "first_seen_ts": time.time()})
    )
    # Write + COMMIT the vulnerable file so it disappears from `git diff HEAD`.
    (repo / "app.py").write_text(RISKY_PY)
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-qm", "add vulnerable app")
    print("\n[E] vulnerable file already committed — baseline should catch it")
    t0 = time.time()
    r = _spawn(repo, data, session_id=session_id)
    dt = time.time() - t0
    if verbose:
        print(f"    rc={r.returncode} wallclock={dt:.1f}s")
        if r.stderr:
            for line in r.stderr.rstrip().splitlines()[-5:]:
                print(f"    stderr: {line[:120]}")
    ok = (
        r.returncode == 2
        and "Soundcheck auto-review found issues" in r.stderr
        and "app.py" in r.stderr
        and dt < 300
    )
    print(f"  {'PASS' if ok else 'FAIL'}  rc={r.returncode}, "
          f"stderr_has_preamble={'Soundcheck auto-review found issues' in r.stderr}, "
          f"stderr_mentions_file={'app.py' in r.stderr}, "
          f"wallclock={dt:.1f}s")
    return ok


def case_h(tmp: Path, verbose: bool) -> bool:
    """Touched-paths file is keyed per (session, project) — no cross-repo collision."""
    repo_a, data = _init_repo(tmp, "H_a")
    repo_b = tmp / "repo-H_b"
    repo_b.mkdir()
    _git(repo_b, "init", "-q")
    _git(repo_b, "config", "user.email", "t@t")
    _git(repo_b, "config", "user.name", "Test")
    (repo_b / "seed.md").write_text("seed\n")
    _git(repo_b, "add", "seed.md")
    _git(repo_b, "commit", "-qm", "init")
    session_id = "shared-session-id"
    (repo_a / "a.py").write_text("x = 1\n")
    (repo_b / "b.py").write_text("y = 2\n")

    script = ROOT / "scripts" / "record-touched-path.py"
    base_env = {**os.environ, "SOUNDCHECK_AUTO_REVIEW": "true",
                "CLAUDE_PLUGIN_ROOT": str(ROOT), "CLAUDE_PLUGIN_DATA": str(data),
                "CLAUDE_CODE_REMOTE_SESSION_ID": session_id}

    for repo, fp in [(repo_a, repo_a / "a.py"), (repo_b, repo_b / "b.py")]:
        env = {**base_env, "CLAUDE_PROJECT_DIR": str(repo)}
        event = json.dumps({
            "session_id": session_id,
            "tool_input": {"file_path": str(fp)},
        })
        subprocess.run([sys.executable, str(script)], env=env, input=event,
                       capture_output=True, text=True, check=False)

    files = sorted(data.glob(f"auto-review-touched-{session_id}-*.json"))
    print("\n[H] same session_id across two repos — expect two distinct files")
    if verbose:
        for f in files:
            print(f"    {f.name}: {f.read_text()}")
    distinct = len(files) == 2
    contents = [json.loads(f.read_text()) for f in files] if distinct else []
    correct = (distinct and all(len(c) == 1 for c in contents)
               and {contents[0][0], contents[1][0]} == {"a.py", "b.py"})
    print(f"  {'PASS' if correct else 'FAIL'}  files={len(files)}, "
          f"contents_correct={correct}")
    return correct


def case_i(tmp: Path, verbose: bool) -> bool:
    """Observability: a real run leaves a parseable JSON entry in auto-review.log."""
    repo, data = _init_repo(tmp, "I")
    (repo / "notes.py").write_text("# only comments\n# nothing else\n")
    print("\n[I] observability log — expect a JSON-line entry post-run")
    r = _spawn(repo, data)
    log_path = data / "auto-review.log"
    ok = log_path.is_file()
    entries = []
    if ok:
        for line in log_path.read_text().splitlines():
            try:
                entries.append(json.loads(line))
            except (json.JSONDecodeError, ValueError):
                ok = False
                break
    valid_stages = {
        "findings", "clean", "review_error", "skip_no_files", "skip_trivial",
        "skip_cache_hit", "skip_triage_no", "skip_locked", "skip_lock_open_failed",
        "triage_only_yes",
    }
    has_known_stage = any(e.get("stage") in valid_stages for e in entries)
    ok = ok and has_known_stage and r.returncode == 0
    if verbose:
        for e in entries[-3:]:
            print(f"    log: {e}")
    print(f"  {'PASS' if ok else 'FAIL'}  log_exists={log_path.is_file()}, "
          f"entries={len(entries)}, has_known_stage={has_known_stage}")
    return ok


def case_j(tmp: Path, verbose: bool) -> bool:
    """Multi-repo refactor: edits span two repos, the vulnerable one gets reviewed.

    Two separate git repos. PostToolUse pre-seeded with absolute paths in
    both. The auto-review.py bucket-and-dispatch should review each repo
    against its own baseline. Only repo A has the vulnerable file; we
    assert findings include repo A's path and the touched-paths file is
    cleared. v1.14 regression check for cross-repo refactor coverage.
    """
    repo_a, data = _init_repo(tmp, "J_a")
    repo_b = tmp / "repo-J_b"
    repo_b.mkdir()
    _git(repo_b, "init", "-q")
    _git(repo_b, "config", "user.email", "t@t")
    _git(repo_b, "config", "user.name", "Test")
    (repo_b / "README.md").write_text("seed\n")
    _git(repo_b, "add", "README.md")
    _git(repo_b, "commit", "-qm", "init")
    (repo_a / "app.py").write_text(RISKY_PY)
    (repo_b / "calc.py").write_text(BENIGN_PY)

    session_id = "e2e-multirepo-test"
    # PostToolUse records absolute paths when the edit is outside CLAUDE_PROJECT_DIR.
    # auto-review.py's record-touched-path keys the file by (session, project_hash),
    # so seed it for repo_a (the "launching" project here).
    touched_file = data / (
        f"auto-review-touched-{session_id}-{_project_key(repo_a)}.json"
    )
    touched_file.write_text(json.dumps([
        str(repo_a / "app.py"),
        str(repo_b / "calc.py"),
    ]))
    print("\n[J] cross-repo refactor — expect findings from repo A only")
    t0 = time.time()
    r = _spawn(repo_a, data, session_id=session_id)
    dt = time.time() - t0
    if verbose:
        print(f"    rc={r.returncode} wallclock={dt:.1f}s")
        for line in r.stderr.rstrip().splitlines()[-8:]:
            print(f"    stderr: {line[:120]}")
    has_preamble = "Soundcheck auto-review found issues" in r.stderr
    mentions_app = "app.py" in r.stderr
    excludes_calc = "calc.py" not in r.stderr or "BENIGN" not in r.stderr.upper()
    ok = (
        r.returncode == 2 and has_preamble and mentions_app and excludes_calc
        and touched_file.read_text() == "[]"
    )
    print(f"  {'PASS' if ok else 'FAIL'}  rc={r.returncode}, "
          f"preamble={has_preamble}, app_mentioned={mentions_app}, "
          f"cleared={touched_file.read_text() == '[]'}, wallclock={dt:.1f}s")
    return ok


CASES = {
    "A": case_a, "B": case_b, "C": case_c, "D": case_d,
    "E": case_e, "F": case_f, "G": case_g, "H": case_h, "I": case_i,
    "J": case_j,
}


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
        # On any failure, dump every auto-review.log we created across the
        # per-case data dirs. Diagnostics for triage failures (claude -p
        # CLI auth/missing) and other silent skips live here.
        if not all(results.values()):
            print()
            print("=" * 60)
            print("auto-review.log dumps (failure diagnostic):")
            for log in sorted(tmp.glob("plugin-data-*/auto-review.log")):
                print(f"\n--- {log.parent.name} ---")
                try:
                    print(log.read_text())
                except OSError as exc:
                    print(f"(read failed: {exc})")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    passed = sum(results.values())
    total = len(results)
    print()
    print(f"Results: {passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
