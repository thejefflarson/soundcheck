#!/usr/bin/env python3
"""Smoke test for the deterministic pr-review regex catalog.

For each pattern in _pr_patterns.PATTERNS, builds an in-memory file with
a matching example and a non-matching counter-example, runs scan_files,
and asserts:

  - The matching example produces exactly one finding from this pattern.
  - The counter-example produces zero findings from this pattern.

This catches accidental over-broad regexes (false-positive cases) and
under-broad regexes (real patterns the rule should catch).

Run: python scripts/test-pr-patterns.py
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _pr_patterns import PATTERNS, scan_files  # noqa: E402


# (pattern_index, ext, matching_source, non_matching_source)
CASES: tuple[tuple[int, str, str, str], ...] = (
    # 0 — yaml.load: match raw yaml.load; safe_load is fine
    (0, ".py",
     "import yaml\nconfig = yaml.load(open('c.yml'))\n",
     "import yaml\nconfig = yaml.safe_load(open('c.yml'))\n"),
    # 1 — pickle.load(s): match both load/loads; pickle.dumps is fine
    (1, ".py",
     "import pickle\nobj = pickle.loads(blob)\n",
     "import pickle\ndata = pickle.dumps({'k': 1})\n"),
    # 2 — subprocess shell=True
    (2, ".py",
     "import subprocess\nsubprocess.run(cmd, shell=True)\n",
     "import subprocess\nsubprocess.run(['ls', '-l', path])\n"),
    # 3 — requests verify=False
    (3, ".py",
     "import requests\nrequests.get(url, verify=False)\n",
     "import requests\nrequests.get(url, verify=True)\n"),
    # 4 — JWT algorithms ['none']
    (4, ".py",
     "import jwt\nclaims = jwt.decode(t, k, algorithms=['none'])\n",
     "import jwt\nclaims = jwt.decode(t, k, algorithms=['HS256'])\n"),
    # 5 — dangerouslySetInnerHTML
    (5, ".jsx",
     "return <div dangerouslySetInnerHTML={{__html: html}} />;\n",
     "return <div>{html}</div>;\n"),
    # 6 — private key in source
    (6, ".pem",
     "-----BEGIN RSA PRIVATE KEY-----\nMIIBOQIBAAJ...\n-----END RSA PRIVATE KEY-----\n",
     "-----BEGIN PUBLIC KEY-----\nMIGfMA0...\n-----END PUBLIC KEY-----\n"),
    # 7 — AWS access key id
    (7, ".env",
     "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
     "AWS_ACCESS_KEY_ID=ASIAIOSFODNN7EXAMPLE\n"),  # ASIA = temp session token; different pattern
)


def main() -> int:
    failures: list[str] = []

    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)

        for pattern_idx, ext, matching, non_matching in CASES:
            pat = PATTERNS[pattern_idx]
            pat_label = f"#{pattern_idx} ({pat.regex.pattern[:40]})"

            # Test the matching case
            match_file = repo / f"match_{pattern_idx}{ext}"
            match_file.write_text(matching, encoding="utf-8")
            findings = scan_files(repo, [match_file.name])
            hits = [f for f in findings if f["skill"] == pat.skill]
            if len(hits) != 1:
                failures.append(
                    f"PATTERN {pat_label}: expected 1 hit on matching source, got {len(hits)}"
                )
            elif hits[0]["severity"] != pat.severity:
                failures.append(
                    f"PATTERN {pat_label}: hit severity {hits[0]['severity']!r}, "
                    f"expected {pat.severity!r}"
                )

            # Test the counter-example
            nm_file = repo / f"nomatch_{pattern_idx}{ext}"
            nm_file.write_text(non_matching, encoding="utf-8")
            findings = scan_files(repo, [nm_file.name])
            hits = [f for f in findings if f["skill"] == pat.skill]
            if len(hits) != 0:
                failures.append(
                    f"PATTERN {pat_label}: FALSE POSITIVE on counter-example "
                    f"({len(hits)} unexpected hits)"
                )

    if failures:
        print("FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"PASS — {len(CASES)} patterns × 2 cases each verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
