#!/usr/bin/env python3
"""
Quarterly threat-radar review — drafts the issue body with real research.

The weekly/quarterly skill-smoke-tests workflow used to open an empty
checklist issue. This script runs the checklist: reads
``docs/threat-radar.md``, fetches external sources (OWASP project pages,
NVD CVE feed) via the ``claude`` CLI with WebSearch + WebFetch tools,
and emits a Markdown report with concrete proposals. The workflow posts
that report as the issue body, so the human closing the ticket is
reviewing a draft rather than starting from zero.

Shells out to ``claude`` — same CLI the rest of the pipeline uses.

Usage:
    python scripts/quarterly-threat-review.py > /tmp/quarterly.md
    python scripts/quarterly-threat-review.py --model sonnet --max-budget-usd 3
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _claude_cli import ClaudeCLIError, run_claude  # noqa: E402

ROOT = Path(__file__).parent.parent
THREAT_RADAR = ROOT / "docs" / "threat-radar.md"

SYSTEM_PROMPT = """\
You draft a quarterly threat-radar review for the Soundcheck security
skills project. You are given the current threat-radar.md and the date
of its last modification. You have WebSearch and WebFetch.

Do all of the following, in order:

1. Check the OWASP LLM Top 10 project page and the OWASP API Security
   Top 10 project page for new drafts, minor revisions, or draft
   categories that post-date the radar's last update.
2. Search NVD, CVE Details, or GitHub Security Advisories for AI-, LLM-,
   prompt-injection-, agent-, or MCP-related CVEs published since the
   radar's last update. Prefer CVEs with clear exploit patterns over
   vendor-specific misconfig advisories.
3. Look for high-signal incident writeups, security-researcher posts, or
   conference talks on AI/LLM/agent vulnerabilities from the same window.
4. For every entry on the `watching` tier of the radar, decide whether
   the evidence you gathered supports promoting it to `candidate`. Be
   conservative — promotion requires at least one concrete exploit
   pattern or reproducible incident, not just mentions in threat blogs.
5. Flag any `shipped` skills whose attack patterns may have drifted based
   on what you found.

Output ONLY a Markdown document with this exact structure. No prose
before or after:

## New or updated external references

Bulleted list. Each item has a one-sentence summary, a date, and a URL.

## CVEs worth noting

Bulleted list of up to 10 most-relevant CVEs published since the radar's
last update. Each item: `CVE-YYYY-NNNNN` — one-sentence summary — link.

## Watching-tier promotion suggestions

For each radar entry on the `watching` tier, emit either
`- **<name>**: promote to candidate — <1-sentence reason with citation>`
or
`- **<name>**: keep watching — <1-sentence reason>`.

## Shipped-skill drift flags

Bulleted list. Each item: skill name — what drifted — citation. Empty
section (with "None observed." body) is valid.

## Proposed actions

Numbered list of the 3–5 concrete things a maintainer should do next.
Include file paths (e.g. `.claude/skills/<name>/SKILL.md`,
`docs/threat-radar.md`) where relevant.

Keep the whole report under 600 words. Cite sources inline as plain URLs."""


def last_radar_update() -> str:
    result = subprocess.run(
        ["git", "log", "-1", "--format=%cs", "--", str(THREAT_RADAR)],
        capture_output=True, text=True, cwd=ROOT, timeout=30,
    )
    return result.stdout.strip() or "never"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Draft the quarterly threat-radar review issue body"
    )
    parser.add_argument("--model", default="sonnet")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--max-budget-usd", type=float, default=3.0)
    parser.add_argument(
        "--radar", type=Path, default=THREAT_RADAR,
        help="Path to threat-radar.md (default: docs/threat-radar.md).",
    )
    args = parser.parse_args()

    if not args.radar.exists():
        print(f"ERROR: threat radar not found: {args.radar}", file=sys.stderr)
        return 1

    radar_text = args.radar.read_text(encoding="utf-8")
    last_touched = last_radar_update()
    now = datetime.now(timezone.utc)
    quarter = ((now.month - 1) // 3) + 1

    user_prompt = (
        f"The current `docs/threat-radar.md` (last modified on "
        f"{last_touched}) is below. Produce the Q{quarter} {now.year} "
        f"review covering changes since {last_touched}.\n\n"
        f"```markdown\n{radar_text}\n```"
    )

    try:
        report = run_claude(
            user_prompt,
            SYSTEM_PROMPT,
            model=args.model,
            cwd=ROOT,
            allowed_tools="WebSearch,WebFetch,Read",
            max_budget_usd=args.max_budget_usd,
            timeout=args.timeout,
        )
    except ClaudeCLIError as exc:
        print(f"ERROR: quarterly review CLI call failed: {exc}",
              file=sys.stderr)
        return 2

    # Prepend a masthead so the reader knows this was model-generated.
    masthead = (
        f"_Automated draft for Q{quarter} {now.year} — "
        f"threat-radar.md last touched {last_touched}. "
        f"Model: {args.model}. Review every claim before acting._\n\n"
    )
    print(masthead + report.strip())
    return 0


if __name__ == "__main__":
    sys.exit(main())
