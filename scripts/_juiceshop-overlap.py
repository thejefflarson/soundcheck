#!/usr/bin/env python3
"""Per-finding overlap analysis for the Juice Shop benchmark run.

Deterministic aggregation, one LLM decision per finding. Avoids
LLM-doing-arithmetic errors.

Phases (each caches its output under .juiceshop-benchmark/overlap/):

  1. extract_findings   — parse review markdown table into structured
                          list of {id, severity, file, line, category,
                          description}. One LLM call.
  2. classify_challenges — read data/static/challenges.yml, mark each
                          challenge source-detectable (in G) or not.
                          One LLM call.
  3. match_findings     — for each finding, ask the judge which G
                          challenge (if any) this finding addresses.
                          Parallel, one LLM call per finding.
  4. overlap_check      — for each FP (matched=null), loop the FN list
                          and ask "does this finding describe the same
                          bug as this FN challenge?" Parallel.
  5. dedupe_fps         — for each FP finding, ask the judge for a
                          canonical bug_id (file + one-line mechanism).
                          Group by bug_id → unique-bug FP count.

Then Python computes precision/recall under strict scoring and
overlap-credited scoring. LLM never adds a number.

Re-run any phase by deleting its cache file.
"""

from __future__ import annotations

import concurrent.futures as futures
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _claude_cli import run_claude  # noqa: E402

ROOT = Path(__file__).parent.parent
BENCH_DIR = ROOT / ".juiceshop-benchmark"
REPO_DIR = BENCH_DIR / "juice-shop"
DUMP = BENCH_DIR / "run-04.json"
CACHE = BENCH_DIR / "overlap"
CACHE.mkdir(exist_ok=True)

MODEL = "sonnet"
MAX_WORKERS = 8


def extract_json(text: str) -> dict | list:
    fenced = re.search(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```",
                       text, re.DOTALL)
    if fenced:
        raw = fenced.group(1)
    else:
        m = re.search(r"[\{\[].*[\}\]]", text, re.DOTALL)
        if not m:
            raise ValueError(f"no JSON in: {text[:400]}")
        raw = m.group(0)
    return json.loads(raw)


def call(prompt: str, system: str, *, cwd: Path | None = None,
         budget: float = 0.5, timeout: int = 600) -> str:
    return run_claude(
        prompt, system,
        model=MODEL, cwd=cwd, timeout=timeout, max_budget_usd=budget,
    )


# ---------------------------------------------------------------------------
# Phase 1 — Extract findings
# ---------------------------------------------------------------------------

EXTRACT_SYSTEM = (
    "You extract structured data from a security-review response. "
    "Return only a JSON array."
)

EXTRACT_PROMPT = """Parse this security-review response and return one JSON entry
per finding. Ignore prose, headers, attack-chain narratives, and
severity legends — only extract rows from the findings table.

Return JSON only:

```json
[
  {{"id": 1, "severity": "...", "file": "...", "line": "...",
    "category": "...", "description": "one sentence", "fix": "one sentence"}}
]
```

--- BEGIN REVIEW ---
{review}
--- END REVIEW ---"""


def phase_extract_findings(review: str) -> list[dict]:
    cache = CACHE / "findings.json"
    if cache.exists():
        return json.loads(cache.read_text())
    print("  [1/5] Extract findings from review markdown...")
    prompt = EXTRACT_PROMPT.format(
        review=review[:80_000].replace("{", "{{").replace("}", "}}"),
    )
    text = call(prompt, EXTRACT_SYSTEM, budget=1.0)
    findings = extract_json(text)
    for i, f in enumerate(findings, 1):
        f["id"] = i
    cache.write_text(json.dumps(findings, indent=2))
    print(f"        extracted {len(findings)} findings")
    return findings


# ---------------------------------------------------------------------------
# Phase 2 — Classify challenges
# ---------------------------------------------------------------------------

CLASSIFY_SYSTEM = (
    "You classify one OWASP Juice Shop challenge as source-detectable "
    "or behavioural. Return JSON only."
)

CLASSIFY_PROMPT = """Challenge:

```json
{challenge}
```

Is this challenge source-detectable? true if a competent auditor
reading the source could name this vulnerability without running the
app, crafting a payload, or doing OSINT. false for behavioural
challenges (CAPTCHA bypass, timing games, security-question OSINT,
steganography, chatbot social engineering, weak-password guessing,
pure UI click-throughs, geo/EXIF puzzles).

Return JSON only:

```json
{{"key": "{key}", "source_detectable": true,
  "reason": "<one sentence>"}}
```
"""


def _classify_one(entry: dict) -> dict:
    slim = {"key": entry.get("key"), "name": entry.get("name"),
            "category": entry.get("category"),
            "description": (entry.get("description") or "")[:400]}
    prompt = CLASSIFY_PROMPT.format(
        challenge=json.dumps(slim).replace("{", "{{").replace("}", "}}"),
        key=entry.get("key"),
    )
    try:
        text = call(prompt, CLASSIFY_SYSTEM, budget=0.25, timeout=180)
    except Exception as exc:
        return {"key": entry.get("key"), "source_detectable": True,
                "reason": f"call failed: {exc!r}"[:200],
                "category": entry.get("category"),
                "description": entry.get("description")}
    try:
        parsed = extract_json(text)
    except (ValueError, json.JSONDecodeError):
        return {"key": entry.get("key"), "source_detectable": True,
                "reason": "parse failure",
                "category": entry.get("category"),
                "description": entry.get("description")}
    # Preserve category+description on the returned record so downstream
    # phases don't need to re-open challenges.yml.
    parsed["category"] = entry.get("category")
    parsed["description"] = entry.get("description")
    return parsed


def phase_classify_challenges() -> list[dict]:
    import yaml
    cache = CACHE / "challenges.json"
    if cache.exists():
        return json.loads(cache.read_text())
    yml = REPO_DIR / "data" / "static" / "challenges.yml"
    entries = yaml.safe_load(yml.read_text())
    print(f"  [2/5] Classify {len(entries)} challenges (parallel, "
          f"{MAX_WORKERS} workers)...")
    results: list[dict] = []
    with futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        pending = {ex.submit(_classify_one, e): e for e in entries}
        for fut in futures.as_completed(pending):
            res = fut.result()
            results.append(res)
            if len(results) % 20 == 0:
                print(f"        {len(results)}/{len(entries)}")
    # Preserve input order for stable output
    order = {e.get("key"): i for i, e in enumerate(entries)}
    results.sort(key=lambda r: order.get(r.get("key"), 10**9))
    cache.write_text(json.dumps(results, indent=2))
    detectable = sum(1 for c in results if c.get("source_detectable"))
    print(f"        {len(results)} total, {detectable} source-detectable (G)")
    return results


# ---------------------------------------------------------------------------
# Phase 3 — Match each finding to a challenge in G (or null)
# ---------------------------------------------------------------------------

MATCH_SYSTEM = (
    "You match one security-review finding against a list of OWASP "
    "Juice Shop challenges. Use tools to Read source files under the "
    "current working directory when verifying. Return JSON only."
)

MATCH_PROMPT = """Finding to classify:

```json
{finding}
```

Candidate challenges (source-detectable subset, G):

```json
{challenges}
```

Task: does this finding address any ONE challenge in G? A finding
matches a challenge iff it names the same vulnerable behaviour at (very
roughly) the same file/route. Read the cited file(s) if unsure.

Return JSON only:

```json
{{"finding_id": {finding_id},
  "matched_key": "<challenge key, or null>",
  "confidence": "high|medium|low",
  "reason": "<one sentence>"}}
```
"""


def _match_one(finding: dict, challenges_str: str) -> dict:
    prompt = MATCH_PROMPT.format(
        finding=json.dumps(finding).replace("{", "{{").replace("}", "}}"),
        challenges=challenges_str,
        finding_id=finding["id"],
    )
    try:
        text = call(prompt, MATCH_SYSTEM, cwd=REPO_DIR, budget=1.0)
    except Exception as exc:
        return {"finding_id": finding["id"], "matched_key": None,
                "confidence": "low", "reason": f"call failed: {exc!r}"[:200]}
    try:
        return extract_json(text)  # type: ignore[return-value]
    except (ValueError, json.JSONDecodeError):
        return {"finding_id": finding["id"], "matched_key": None,
                "confidence": "low", "reason": "parse failure"}


def phase_match(findings: list[dict],
                challenges: list[dict]) -> list[dict]:
    cache = CACHE / "matches.json"
    if cache.exists():
        return json.loads(cache.read_text())
    G = [c for c in challenges if c.get("source_detectable")]
    challenges_slim = [
        {"key": c["key"], "category": c.get("category"),
         "description": c.get("description")}
        for c in G
    ]
    # Escape braces once — same content passed to every worker.
    challenges_str = (
        json.dumps(challenges_slim, indent=2)
        .replace("{", "{{").replace("}", "}}")
    )
    print(f"  [3/5] Match {len(findings)} findings against |G|={len(G)}"
          f" challenges (parallel, {MAX_WORKERS} workers)...")
    results: list[dict] = []
    with futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        pending = {ex.submit(_match_one, f, challenges_str): f
                   for f in findings}
        for fut in futures.as_completed(pending):
            res = fut.result()
            results.append(res)
            if len(results) % 10 == 0:
                print(f"        {len(results)}/{len(findings)}")
    results.sort(key=lambda r: r["finding_id"])
    cache.write_text(json.dumps(results, indent=2))
    matched = [r for r in results if r.get("matched_key")]
    print(f"        {len(matched)}/{len(results)} matched to a challenge")
    return results


# ---------------------------------------------------------------------------
# Phase 4 — Per-FP overlap check against FN
# ---------------------------------------------------------------------------

OVERLAP_SYSTEM = (
    "You determine whether a security finding overlaps with a "
    "specific unmatched Juice Shop challenge. Use tools to verify. "
    "Return JSON only."
)

OVERLAP_PROMPT = """Finding:

```json
{finding}
```

The following Juice Shop challenges were left unmatched under strict
1:1 scoring. Does this finding describe the same underlying bug as
ANY of them, even if imperfectly? Match at most one — pick the best.

```json
{challenges}
```

Return JSON only:

```json
{{"finding_id": {finding_id},
  "overlapping_key": "<challenge key, or null>",
  "confidence": "high|medium|low",
  "reason": "<one sentence>"}}
```
"""


def _overlap_one(finding: dict, fn_str: str) -> dict:
    prompt = OVERLAP_PROMPT.format(
        finding=json.dumps(finding).replace("{", "{{").replace("}", "}}"),
        challenges=fn_str,
        finding_id=finding["id"],
    )
    try:
        text = call(prompt, OVERLAP_SYSTEM, cwd=REPO_DIR, budget=1.0)
    except Exception as exc:
        return {"finding_id": finding["id"], "overlapping_key": None,
                "confidence": "low", "reason": f"call failed: {exc!r}"[:200]}
    try:
        return extract_json(text)  # type: ignore[return-value]
    except (ValueError, json.JSONDecodeError):
        return {"finding_id": finding["id"], "overlapping_key": None,
                "confidence": "low", "reason": "parse failure"}


def phase_overlap(findings: list[dict], challenges: list[dict],
                  matches: list[dict]) -> list[dict]:
    cache = CACHE / "overlap.json"
    if cache.exists():
        return json.loads(cache.read_text())
    matched_keys = {m["matched_key"] for m in matches if m.get("matched_key")}
    G = [c for c in challenges if c.get("source_detectable")]
    fn = [c for c in G if c["key"] not in matched_keys]
    fn_slim = [
        {"key": c["key"], "category": c.get("category"),
         "description": c.get("description")}
        for c in fn
    ]
    fn_str = (
        json.dumps(fn_slim, indent=2)
        .replace("{", "{{").replace("}", "}}")
    )
    fp_findings = [f for f in findings
                   if not next((m["matched_key"] for m in matches
                                if m["finding_id"] == f["id"]), None)]
    print(f"  [4/5] Overlap-check {len(fp_findings)} FPs against "
          f"{len(fn)} FN challenges...")
    results: list[dict] = []
    with futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        pending = {ex.submit(_overlap_one, f, fn_str): f
                   for f in fp_findings}
        for fut in futures.as_completed(pending):
            res = fut.result()
            results.append(res)
    results.sort(key=lambda r: r["finding_id"])
    cache.write_text(json.dumps(results, indent=2))
    overlapping = [r for r in results if r.get("overlapping_key")]
    print(f"        {len(overlapping)}/{len(fp_findings)} overlap with an FN")
    return results


# ---------------------------------------------------------------------------
# Phase 5 — Dedupe FPs by canonical bug id
# ---------------------------------------------------------------------------

DEDUPE_SYSTEM = (
    "You produce a canonical bug identifier for a security finding. "
    "Return JSON only."
)

DEDUPE_PROMPT = """Assign a canonical bug id to this finding — the shape is
`<file_or_component>::<one-line-mechanism-key>`. Two findings that
describe the same underlying vulnerability must produce the same
bug id. Different vulns in the same file must produce different ids.
Prefer short, mechanism-focused keys (e.g. `chatbot.ts::jwt-verify-no-algs`,
not `chatbot.ts::authentication-bug`).

Finding:

```json
{finding}
```

Return JSON only:

```json
{{"finding_id": {finding_id}, "bug_id": "<file>::<mechanism>",
  "is_hallucination": <true/false — cite behaviour or code that does not exist in this repo>,
  "reason": "<one sentence>"}}
```
"""


def _dedupe_one(finding: dict) -> dict:
    prompt = DEDUPE_PROMPT.format(
        finding=json.dumps(finding).replace("{", "{{").replace("}", "}}"),
        finding_id=finding["id"],
    )
    try:
        text = call(prompt, DEDUPE_SYSTEM, cwd=REPO_DIR, budget=0.75)
    except Exception as exc:
        return {"finding_id": finding["id"],
                "bug_id": f"unknown::{finding['id']}",
                "is_hallucination": False,
                "reason": f"call failed: {exc!r}"[:200]}
    try:
        return extract_json(text)  # type: ignore[return-value]
    except (ValueError, json.JSONDecodeError):
        return {"finding_id": finding["id"], "bug_id": f"unknown::{finding['id']}",
                "is_hallucination": False, "reason": "parse failure"}


def phase_dedupe(findings: list[dict], matches: list[dict],
                 overlaps: list[dict]) -> list[dict]:
    cache = CACHE / "dedupe.json"
    if cache.exists():
        return json.loads(cache.read_text())
    matched_ids = {m["finding_id"] for m in matches
                   if m.get("matched_key")}
    overlapping_ids = {o["finding_id"] for o in overlaps
                       if o.get("overlapping_key")}
    fp_ids = {f["id"] for f in findings} - matched_ids - overlapping_ids
    fp_findings = [f for f in findings if f["id"] in fp_ids]
    print(f"  [5/5] Dedupe {len(fp_findings)} residual FPs by canonical "
          f"bug id...")
    results: list[dict] = []
    with futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        pending = {ex.submit(_dedupe_one, f): f for f in fp_findings}
        for fut in futures.as_completed(pending):
            results.append(fut.result())
    results.sort(key=lambda r: r["finding_id"])
    cache.write_text(json.dumps(results, indent=2))
    unique_bug_ids = {r["bug_id"] for r in results}
    halluc = sum(1 for r in results if r.get("is_hallucination"))
    print(f"        {len(unique_bug_ids)} unique bug ids ({halluc} "
          f"hallucinations flagged)")
    return results


# ---------------------------------------------------------------------------
# Report — all deterministic
# ---------------------------------------------------------------------------

def report(findings, challenges, matches, overlaps, dedupe):
    G = [c for c in challenges if c.get("source_detectable")]
    G_keys = {c["key"] for c in G}

    matched_map = {m["finding_id"]: m for m in matches}
    dedupe_map = {d["finding_id"]: d for d in dedupe}

    # Finding-level classification under strict 1:1 matching.
    # A challenge can be paired with at most one finding. When N > 1
    # findings match the same challenge, the first wins (arbitrary but
    # deterministic — sort by finding id). The others become "duplicate"
    # findings, which under strict scoring count as FP (still unpaired).
    matched_findings_by_challenge: dict[str, list[int]] = {}
    for f in findings:
        k = matched_map[f["id"]].get("matched_key")
        if k and k in G_keys:
            matched_findings_by_challenge.setdefault(k, []).append(f["id"])

    strict_paired_ids: set[int] = set()
    for ids in matched_findings_by_challenge.values():
        strict_paired_ids.add(min(ids))
    strict_duplicate_ids = {
        fid for ids in matched_findings_by_challenge.values()
        for fid in ids if fid not in strict_paired_ids
    }
    strict_unmatched_ids = {
        f["id"] for f in findings
        if not matched_map[f["id"]].get("matched_key")
    }

    strict_tp = len(strict_paired_ids)                 # findings paired 1:1 with a G challenge
    strict_fp = len(strict_duplicate_ids) + len(strict_unmatched_ids)
    strict_tp_keys = set(matched_findings_by_challenge.keys())
    strict_fn = len(G_keys - strict_tp_keys)

    strict_precision = strict_tp / (strict_tp + strict_fp) if strict_tp + strict_fp else 0.0
    strict_recall = strict_tp / (strict_tp + strict_fn) if strict_tp + strict_fn else 0.0
    strict_f1 = (2 * strict_precision * strict_recall
                 / (strict_precision + strict_recall)
                 if strict_precision + strict_recall else 0.0)

    # Overlap credit: for each strict-FP finding, if the overlap judge
    # matched it to a currently-unmatched G challenge, promote it to TP.
    overlap_map = {o["finding_id"]: o.get("overlapping_key")
                   for o in overlaps}
    generous_paired_ids = set(strict_paired_ids)
    generous_tp_keys = set(strict_tp_keys)
    for fid in sorted(strict_duplicate_ids | strict_unmatched_ids):
        k = overlap_map.get(fid)
        if k and k in G_keys and k not in generous_tp_keys:
            generous_paired_ids.add(fid)
            generous_tp_keys.add(k)

    generous_unpaired_ids = {f["id"] for f in findings} - generous_paired_ids
    # Dedupe residual FPs by canonical bug id.
    residual_bug_ids: dict[str, int] = {}   # bug_id -> first finding id
    hallucinated_bug_ids: set[str] = set()
    for fid in generous_unpaired_ids:
        d = dedupe_map.get(fid)
        if not d:
            continue
        bug_id = d.get("bug_id", f"unknown::{fid}")
        residual_bug_ids.setdefault(bug_id, fid)
        if d.get("is_hallucination"):
            hallucinated_bug_ids.add(bug_id)

    gen_tp = len(generous_paired_ids)
    gen_fp_unique_bugs = len(residual_bug_ids)          # unique unpaired bugs
    gen_fp_raw_findings = len(generous_unpaired_ids)    # raw unpaired findings
    gen_hallucinations = len(hallucinated_bug_ids)
    gen_off_list_real = gen_fp_unique_bugs - gen_hallucinations
    gen_fn = len(G_keys - generous_tp_keys)

    gen_precision = gen_tp / (gen_tp + gen_fp_unique_bugs) if gen_tp + gen_fp_unique_bugs else 0.0
    gen_recall = gen_tp / (gen_tp + gen_fn) if gen_tp + gen_fn else 0.0
    gen_f1 = (2 * gen_precision * gen_recall
              / (gen_precision + gen_recall)
              if gen_precision + gen_recall else 0.0)

    print("\n" + "=" * 68)
    print("Juice Shop /security-review — deterministic overlap report")
    print("=" * 68)
    print(f"Findings extracted:       {len(findings)}")
    print(f"|G| source-detectable:    {len(G)} challenges")
    print()
    print("Finding-level classification (strict 1 finding : 1 challenge)")
    print(f"  {len(strict_paired_ids)} findings paired to a distinct challenge (TP)")
    print(f"  {len(strict_duplicate_ids)} findings matched a challenge already claimed by another finding")
    print(f"  {len(strict_unmatched_ids)} findings matched no challenge")
    print(f"  ------------------------------------------------------------")
    print(f"  TP {strict_tp:>4}    FP {strict_fp:>4}    FN {strict_fn:>4}")
    print(f"  Check: TP + FP = {strict_tp + strict_fp} (must == findings {len(findings)})")
    print(f"         TP + FN = {strict_tp + strict_fn} (must == |G| {len(G_keys)})")
    print(f"  Precision {strict_precision:>6.1%}   Recall {strict_recall:>6.1%}   F1 {strict_f1:>6.1%}")
    print()
    n_overlap = sum(1 for fid in (strict_duplicate_ids | strict_unmatched_ids)
                    if overlap_map.get(fid) in G_keys)
    n_new_keys = len(generous_tp_keys) - len(strict_tp_keys)
    print(f"Overlap analysis")
    print(f"  {n_overlap} unpaired findings overlap an FN challenge")
    print(f"  → recovers {n_new_keys} additional distinct FN challenges as TP")
    print()
    print("Generous scoring (overlap credit + residual-FP dedup)")
    print(f"  TP {gen_tp:>4}    FP {gen_fp_unique_bugs:>4} unique bugs   FN {gen_fn:>4}")
    print(f"    residual FPs: {gen_fp_raw_findings} raw findings → "
          f"{gen_fp_unique_bugs} unique bugs "
          f"({gen_off_list_real} off-list real, {gen_hallucinations} hallucinations)")
    print(f"  Check: TP + FN = {gen_tp + gen_fn} (must == |G| {len(G_keys)})")
    print(f"  Precision {gen_precision:>6.1%}   Recall {gen_recall:>6.1%}   F1 {gen_f1:>6.1%}")

    (CACHE / "report.json").write_text(json.dumps({
        "totals": {"findings": len(findings), "G": len(G_keys)},
        "strict": {
            "tp": strict_tp, "fp": strict_fp, "fn": strict_fn,
            "duplicate_findings": len(strict_duplicate_ids),
            "unmatched_findings": len(strict_unmatched_ids),
            "precision": strict_precision, "recall": strict_recall,
            "f1": strict_f1,
        },
        "overlap": {
            "unpaired_findings_matching_fn": n_overlap,
            "additional_challenges_recovered": n_new_keys,
        },
        "generous": {
            "tp": gen_tp,
            "fp_unique_bugs": gen_fp_unique_bugs,
            "fp_raw_findings": gen_fp_raw_findings,
            "fn": gen_fn,
            "off_list_real_bugs": gen_off_list_real,
            "hallucinations": gen_hallucinations,
            "precision": gen_precision, "recall": gen_recall, "f1": gen_f1,
        },
    }, indent=2))


def main() -> int:
    review = json.loads(DUMP.read_text())["findings"]
    findings = phase_extract_findings(review)
    challenges = phase_classify_challenges()
    matches = phase_match(findings, challenges)
    overlaps = phase_overlap(findings, challenges, matches)
    dedupe = phase_dedupe(findings, matches, overlaps)
    report(findings, challenges, matches, overlaps, dedupe)
    return 0


if __name__ == "__main__":
    sys.exit(main())
