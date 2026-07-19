#!/usr/bin/env python3
"""For each unmatched finding, ask the judge for its CLOSEST G challenge.

Unlike phase 4 (which restricts to FN challenges — challenges not yet
matched by any finding), this pairs each residual FP with its single
closest challenge regardless of whether that challenge is already
claimed. Useful for eyeballing which residuals are genuinely off-list
vs. near-misses of a challenge that was scored to a different finding.

Output: one row per unmatched finding, showing the finding and its
closest candidate G challenge with confidence.
"""

from __future__ import annotations
import concurrent.futures as futures
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _claude_cli import run_claude

ROOT = Path(__file__).parent.parent
OVL = ROOT / ".juiceshop-benchmark" / "overlap"
REPO_DIR = ROOT / ".juiceshop-benchmark" / "juice-shop"
MAX_WORKERS = 8

findings = json.loads((OVL / "findings.json").read_text())
challenges = json.loads((OVL / "challenges.json").read_text())
matches = json.loads((OVL / "matches.json").read_text())

G = [c for c in challenges if c.get("source_detectable")]
G_keys = {c["key"] for c in G}
G_slim = [{"key": c["key"], "category": c.get("category"),
           "description": c.get("description")} for c in G]
G_json = json.dumps(G_slim, indent=2).replace("{", "{{").replace("}", "}}")

by_match_id = {m["finding_id"]: m for m in matches}
unmatched = [f for f in findings
             if not by_match_id[f["id"]].get("matched_key")]

SYSTEM = (
    "You pair a security-review finding with the single closest Juice "
    "Shop challenge. Read the cited source file if you need to verify. "
    "Return JSON only."
)

PROMPT = """Finding:

```json
{finding}
```

Which single challenge from the source-detectable set G is the CLOSEST
match to this finding? Pick one even if the match is imperfect. If the
finding truly has no plausible relationship to any challenge in G,
return null for closest_key.

Confidence guide:
  high    = same bug, same file, same mechanism
  medium  = same bug class, related file, or same mechanism at a
            different callsite than the challenge planted it
  low     = tenuous — same category only, or you had to reach

Candidate G challenges:

```json
{G}
```

Return JSON only:

```json
{{"finding_id": {fid},
  "closest_key": "<challenge key or null>",
  "confidence": "high|medium|low",
  "reason": "<one sentence>"}}
```
"""


def _closest_one(finding: dict) -> dict:
    prompt = PROMPT.format(
        finding=json.dumps(finding).replace("{", "{{").replace("}", "}}"),
        G=G_json, fid=finding["id"],
    )
    try:
        text = run_claude(prompt, SYSTEM, model="sonnet",
                          cwd=REPO_DIR, timeout=300, max_budget_usd=1.0)
    except Exception as exc:
        return {"finding_id": finding["id"], "closest_key": None,
                "confidence": "low",
                "reason": f"call failed: {exc!r}"[:200]}
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    raw = fenced.group(1) if fenced else re.search(r"\{.*\}", text, re.DOTALL)
    if not fenced:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        raw = m.group(0) if m else None
    if not raw:
        return {"finding_id": finding["id"], "closest_key": None,
                "confidence": "low", "reason": "parse failure"}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"finding_id": finding["id"], "closest_key": None,
                "confidence": "low", "reason": "parse failure"}


print(f"Pairing {len(unmatched)} unmatched findings against |G|={len(G)}"
      f" (parallel, {MAX_WORKERS} workers)...")
results: list[dict] = []
with futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
    pending = {ex.submit(_closest_one, f): f for f in unmatched}
    for fut in futures.as_completed(pending):
        results.append(fut.result())
        if len(results) % 10 == 0:
            print(f"  {len(results)}/{len(unmatched)}")
results.sort(key=lambda r: r["finding_id"])

(OVL / "closest.json").write_text(json.dumps(results, indent=2))

# Also determine which G keys are matched by SOME finding (any TP).
matched_G_keys = {m["matched_key"] for m in matches
                  if m.get("matched_key") in G_keys}

# Render report
finding_by_id = {f["id"]: f for f in findings}
challenge_by_key = {c["key"]: c for c in challenges}


def wrap(text: str, width: int = 90) -> str:
    return (text or "").replace("\n", " ")[:width]


print("\n" + "=" * 100)
print("Residual FP findings paired with closest G challenge")
print("=" * 100)

# Group: by closest_key so we can see clustering
from collections import defaultdict
by_ck = defaultdict(list)
for r in results:
    by_ck[r.get("closest_key")].append(r)

for ck, rs in sorted(by_ck.items(), key=lambda kv: -len(kv[1])):
    if ck is None:
        header = "-- NO CLOSE MATCH (genuinely off-list) --"
    else:
        c = challenge_by_key.get(ck, {})
        state = "already-matched" if ck in matched_G_keys else "unmatched (was FN)"
        header = f"{ck} [{state}] — {c.get('name', '?')}"
    print(f"\n{'=' * 100}")
    print(f"{header}   ({len(rs)} finding{'s' if len(rs)>1 else ''})")
    if ck:
        print(f"  challenge desc: {wrap(c.get('description', ''))}")
    for r in rs:
        f = finding_by_id[r["finding_id"]]
        print(f"  #{f['id']}  {f.get('file','?')}:{f.get('line','?')}  "
              f"[conf {r.get('confidence','?')}]  [{f.get('category','?')}]")
        print(f"       {wrap(f.get('description',''))}")
        print(f"       WHY: {wrap(r.get('reason',''))}")
