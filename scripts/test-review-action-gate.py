#!/usr/bin/env python3
"""Unit tests for security-review-action.py's fail-closed gate logic.

Three behaviors, all of which decide whether the PR gate blocks, passes, or
fails closed:

1. is_doc_only — a deny-list skip. Unknown/extensionless files and scriptable
   or manifest files (.svg, .txt, .mdx) must NOT be treated as doc-only.
   .mdx embeds and executes JSX at build time, so it is code.
2. _is_blocking_severity — normalizes case/space and fails closed on any
   severity outside the known non-blocking set, so a hijacked reviewer can't
   slip a finding past with "high" or a novel label.
3. get_changed_files — raises DiffError on any failure to compute the diff,
   so a failed diff can never be mistaken for "nothing changed" (fail-open).

Usage:
    python scripts/test-review-action-gate.py
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "security_review_action",
    Path(__file__).with_name("security-review-action.py"),
)
_MOD = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MOD)
is_doc_only = _MOD.is_doc_only
_is_blocking_severity = _MOD._is_blocking_severity
get_changed_files = _MOD.get_changed_files
DiffError = _MOD.DiffError

# (files, expected) — expected True means "skip (doc-only)".
DOC_ONLY_CASES: list[tuple[list[str], bool]] = [
    ([], False),                                  # nothing changed != doc-only
    (["README.md"], True),
    (["docs/guide.md", "assets/logo.png"], True),
    (["notes.RST", "Diagram.PNG"], True),         # case-insensitive
    (["README.md", "src/app.py"], False),         # any code -> review
    (["requirements.txt"], False),                # .txt manifest -> review
    (["icon.svg"], False),                        # svg can carry script
    (["page.mdx"], False),                        # mdx executes JSX -> review
    (["README.md", "page.mdx"], False),           # one mdx taints the set
    (["Dockerfile"], False),                      # extensionless -> review
    (["Makefile", "README.md"], False),
    (["config.yaml"], False),
    ([".github/workflows/ci.yml"], False),
    (["CLAUDE.md"], False),                       # agent instructions -> review
    (["AGENTS.md"], False),
    ([".claude/skills/injection/SKILL.md"], False),  # reviewer's own prompt
    ([".claude/hooks/notes.md"], False),          # anything under .claude/
    (["docs/guide.md", "CLAUDE.md"], False),      # one instruction file taints
]

# (severity, expected_blocking) — fail closed on anything not clearly non-blocking.
SEVERITY_CASES: list[tuple[object, bool]] = [
    ("Critical", True),
    ("High", True),
    ("critical", True),        # case-insensitive
    ("HIGH", True),
    ("Critical ", True),       # trailing space
    (" high", True),
    ("Medium", False),
    ("Low", False),
    ("medium", False),
    ("  low  ", False),
    ("", True),                # empty -> fail closed
    (None, True),              # missing -> fail closed
    ("Severe", True),          # novel label -> fail closed
    ("informational", True),   # not a recognized non-blocking severity
]


def _check(name: str, got: object, expected: object, failures: list[str]) -> None:
    if got != expected:
        failures.append(f"FAIL: {name} = {got!r}, expected {expected!r}")
        print(f"FAIL: {name} = {got!r}, expected {expected!r}")
    else:
        print(f"ok:   {name} = {got!r}")


def _test_get_changed_files(failures: list[str]) -> None:
    # Invalid ref is rejected before any subprocess runs.
    try:
        get_changed_files(Path("."), "bad ref; rm -rf /")
        failures.append("FAIL: get_changed_files accepted an invalid ref")
        print("FAIL: get_changed_files accepted an invalid ref")
    except DiffError:
        print("ok:   get_changed_files raises DiffError on invalid ref")

    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        env_setup = [
            ["git", "init", "-q"],
            ["git", "config", "user.email", "t@t"],
            ["git", "config", "user.name", "t"],
            ["git", "commit", "-q", "--allow-empty", "-m", "init"],
        ]
        for cmd in env_setup:
            subprocess.run(cmd, cwd=repo, check=True,
                           capture_output=True, text=True)
        # Clean tree vs HEAD: a *successful* empty diff returns [], not an error.
        _check("get_changed_files(clean repo, HEAD)",
               get_changed_files(repo, "HEAD"), [], failures)
        # Well-formed ref that git can't resolve must fail closed, not return [].
        try:
            get_changed_files(repo, "deadbeefdeadbeef")
            failures.append("FAIL: get_changed_files returned on unresolvable ref")
            print("FAIL: get_changed_files returned on unresolvable ref")
        except DiffError:
            print("ok:   get_changed_files raises DiffError on unresolvable ref")


def main() -> int:
    failures: list[str] = []

    for files, expected in DOC_ONLY_CASES:
        _check(f"is_doc_only({files!r})", is_doc_only(files), expected, failures)
    for sev, expected in SEVERITY_CASES:
        _check(f"_is_blocking_severity({sev!r})",
               _is_blocking_severity(sev), expected, failures)
    _test_get_changed_files(failures)

    if failures:
        print(f"\n{len(failures)} failure(s)")
        return 1
    print("\nAll cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
