#!/usr/bin/env python3
"""Unit test for security-review-action.py's doc-only skip gate.

The gate decides whether a changed-file set is inert documentation/images
(skip, no model call) or contains anything reviewable (run). It is a
deny-list by design, so unknown/extensionless files and scriptable or
manifest files (.svg, .txt) must NOT be treated as doc-only.

Usage:
    python scripts/test-review-action-gate.py
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "security_review_action",
    Path(__file__).with_name("security-review-action.py"),
)
_MOD = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MOD)
is_doc_only = _MOD.is_doc_only

# (files, expected) — expected True means "skip (doc-only)".
CASES: list[tuple[list[str], bool]] = [
    ([], False),                                  # nothing changed != doc-only
    (["README.md"], True),
    (["docs/guide.md", "assets/logo.png"], True),
    (["notes.RST", "Diagram.PNG"], True),         # case-insensitive
    (["README.md", "src/app.py"], False),         # any code -> review
    (["requirements.txt"], False),                # .txt manifest -> review
    (["icon.svg"], False),                        # svg can carry script
    (["Dockerfile"], False),                      # extensionless -> review
    (["Makefile", "README.md"], False),
    (["config.yaml"], False),
    ([".github/workflows/ci.yml"], False),
]


def main() -> int:
    failures = 0
    for files, expected in CASES:
        got = is_doc_only(files)
        if got != expected:
            failures += 1
            print(f"FAIL: is_doc_only({files!r}) = {got}, expected {expected}")
        else:
            print(f"ok:   is_doc_only({files!r}) = {got}")
    if failures:
        print(f"\n{failures} failure(s)")
        return 1
    print(f"\nAll {len(CASES)} cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
