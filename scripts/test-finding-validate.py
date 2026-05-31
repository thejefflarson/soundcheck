#!/usr/bin/env python3
"""Fixture-based ablation test for the finding-validate subagent.

Dispatches `finding-validate` against a hand-crafted set of findings
against vaultwarden code at a known commit. Half the findings are
known-spurious (the cited file has the defense the finding claims is
missing); half are known-real. A working validator drops the spurious
ones and keeps the real ones.

This isolates Stage 2.5 from the haiku non-determinism that swamps the
upstream pipeline. One Claude call, ~30s, deterministic structure.

Re-run after any change to .claude/agents/finding-validate.md to confirm no
regression.

Usage:
    python scripts/test-finding-validate.py
    python scripts/test-finding-validate.py --model sonnet
    python scripts/test-finding-validate.py --verbose
"""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _claude_cli import run_claude, ClaudeCLIError  # noqa: E402

ROOT = Path(__file__).parent.parent
AGENT_PATH = ROOT / ".claude" / "agents" / "finding-validate.md"
VAULTWARDEN_DIR = Path.home() / ".cache" / "soundcheck-eval" / "repos" / "vaultwarden"
PINNED_SHA = "d626ea8"  # captured 2026-05-27

# Minimal threat model — finding-validate uses it for context only.
THREAT_MODEL = {
    "purpose": "Self-hosted Bitwarden-compatible password manager server.",
    "deployment": "Long-running HTTPS server, exposed to the public internet.",
    "trusted_inputs": ["maintainer-committed Rust source", "config.json from operator"],
    "untrusted_inputs": [
        "HTTP request bodies and headers",
        "OAuth/OIDC provider responses",
        "user-uploaded vault items and attachments",
    ],
}

# 9 findings: 4 known-spurious (validator SHOULD drop) + 5 known-real (KEEP).
# Each fixture entry: index in array, expected_drop, justification.
FIXTURE = [
    # 0 — spurious: rate limit IS present at this exact line
    {
        "severity": "High", "file": "src/api/identity.rs", "line": 189,
        "skill": "authentication-failures",
        "finding": "Login endpoint has no rate limit; attacker can credential-stuff at line speed.",
        "fix": "Add a per-IP rate limit to the login handler.",
        "_expected_drop": True,
        "_why": "identity.rs:189 IS `crate::ratelimit::check_limit_login(&ip.ip)?;` — the guard is present.",
    },
    # 1 — spurious: ct_eq (constant-time) IS used at this line
    {
        "severity": "High", "file": "src/db/models/auth_request.rs", "line": 178,
        "skill": "crypto-library-misuse",
        "finding": "Access-code comparison uses == which is timing-sensitive; attacker can extract the code byte-by-byte.",
        "fix": "Switch to subtle::ConstantTimeEq.",
        "_expected_drop": True,
        "_why": "auth_request.rs:178 IS `ct_eq(&self.access_code, access_code)` — constant-time already.",
    },
    # 2 — spurious: query IS parameterized via .bind::<Text>
    {
        "severity": "Critical", "file": "src/db/mod.rs", "line": 420,
        "skill": "injection",
        "finding": "Filename is concatenated into a SQL statement, enabling SQL injection.",
        "fix": "Use a parameterized query.",
        "_expected_drop": True,
        "_why": "db/mod.rs:420 IS `diesel::sql_query(\"VACUUM INTO ?\").bind::<Text, _>(&backup_file)` — parameterized.",
    },
    # 3 — spurious: rand::thread_rng() is a CSPRNG in Rust
    {
        "severity": "High", "file": "src/util.rs", "line": 935,
        "skill": "cryptographic-failures",
        "finding": "Uses rand::thread_rng() which is not cryptographically secure; attacker can predict tokens.",
        "fix": "Switch to a CSPRNG like OsRng.",
        "_expected_drop": True,
        "_why": "rand::thread_rng() IS a CSPRNG in Rust (ChaCha12 seeded from OS entropy). The claim is false.",
    },
    # 4 — REAL: missing HSTS header
    {
        "severity": "High", "file": "src/util.rs", "line": 39,
        "skill": "insecure-design",
        "finding": "No Strict-Transport-Security header set. MITM can downgrade to HTTP and steal session cookies.",
        "fix": "Add Strict-Transport-Security to the AppHeaders fairing.",
        "_expected_drop": False,
        "_why": "Genuinely missing — confirmed in the live security-review output.",
    },
    # 5 — REAL: SSO email-only matching
    {
        "severity": "High", "file": "src/api/identity.rs", "line": 260,
        "skill": "authentication-failures",
        "finding": "SSO login matches users by email alone without verifying the SSO identifier; an attacker controlling a different OIDC account with the victim's email can sign in as the victim.",
        "fix": "Reject login if no SsoUser link exists; do not auto-link on email match.",
        "_expected_drop": False,
        "_why": "Genuinely missing — confirmed in the live security-review output.",
    },
    # 6 — REAL: admin open redirect
    {
        "severity": "High", "file": "src/api/admin.rs", "line": 216,
        "skill": "open-redirect",
        "finding": "redirect parameter from login form is concatenated into redirect URL without validation, enabling open redirect to attacker-controlled hosts.",
        "fix": "Validate the redirect against a relative-path allowlist.",
        "_expected_drop": False,
        "_why": "Genuinely missing — confirmed in the live security-review output.",
    },
    # 7 — REAL: X-Forwarded-Proto/Host trust
    {
        "severity": "High", "file": "src/auth.rs", "line": 553,
        "skill": "header-injection",
        "finding": "X-Forwarded-Proto and X-Forwarded-Host headers are trusted without validation when DOMAIN is unset, letting attackers craft a malicious host URL.",
        "fix": "Validate against an allowlist or require DOMAIN configuration.",
        "_expected_drop": False,
        "_why": "Genuinely missing — confirmed in the live security-review output.",
    },
    # 8 — REAL: missing rate limit on password-reset email
    {
        "severity": "Medium", "file": "src/api/core/accounts.rs", "line": 943,
        "skill": "insecure-design",
        "finding": "Password-reset email endpoint has no rate limit; enables email-address enumeration and victim spam.",
        "fix": "Wrap the endpoint with a per-email rate limit.",
        "_expected_drop": False,
        "_why": "Genuinely missing — confirmed in the live security-review output.",
    },
]


def load_agent_body(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            return text[end + 4:]
    return text


def build_user_prompt() -> str:
    findings = [{k: v for k, v in entry.items() if not k.startswith("_")}
                for entry in FIXTURE]
    return (
        "Here is the threat model JSON for context:\n\n"
        f"{json.dumps(THREAT_MODEL, indent=2)}\n\n"
        "Here is the merged findings array (0-indexed). Return ONLY a JSON array "
        "of 0-based indices to DROP, per your instructions:\n\n"
        f"{json.dumps(findings, indent=2)}"
    )


def extract_drop_indices(response: str) -> list[int]:
    """Extract a JSON array of integers from the response."""
    # Try fenced block first, then bare array
    fenced = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", response, re.DOTALL)
    if fenced:
        text = fenced.group(1)
    else:
        bare = re.search(r"\[[\d,\s]*\]", response, re.DOTALL)
        text = bare.group(0) if bare else response
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(parsed, list):
        return []
    return [int(x) for x in parsed if isinstance(x, int)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="haiku")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if not VAULTWARDEN_DIR.exists():
        print(f"ERROR: vaultwarden checkout not found at {VAULTWARDEN_DIR}")
        print("Run: python scripts/benchmark-eval.py --repo vaultwarden (any run pulls it)")
        return 2

    # Sanity check the pinned SHA — line numbers are tied to this commit
    import subprocess
    head = subprocess.run(
        ["git", "-C", str(VAULTWARDEN_DIR), "rev-parse", "--short", "HEAD"],
        capture_output=True, text=True,
    ).stdout.strip()
    if head != PINNED_SHA:
        print(f"WARNING: vaultwarden HEAD is {head}, fixture was captured at {PINNED_SHA}.")
        print("Line numbers may not match. Continuing anyway.\n")

    system_prompt = load_agent_body(AGENT_PATH)
    user_prompt = build_user_prompt()

    print(f"Dispatching finding-validate ({args.model}) on {len(FIXTURE)} findings...")
    try:
        response = run_claude(
            user_prompt,
            system_prompt,
            model=args.model,
            cwd=VAULTWARDEN_DIR,
            allowed_tools="Read,Glob,Grep",
            max_budget_usd=2.0,
            timeout=600,
        )
    except ClaudeCLIError as exc:
        print(f"ERROR: {exc}")
        return 2

    if args.verbose:
        print(f"\n--- Raw response ---\n{response}\n--- end ---\n")

    dropped = set(extract_drop_indices(response))
    expected_drop = {i for i, e in enumerate(FIXTURE) if e["_expected_drop"]}
    expected_keep = {i for i, e in enumerate(FIXTURE) if not e["_expected_drop"]}

    print(f"\nValidator dropped: {sorted(dropped) or '[]'}")
    print(f"Expected drops:    {sorted(expected_drop)}")
    print()

    # True/false positives/negatives from the validator's perspective
    correct_drops = dropped & expected_drop      # validator dropped a real noise
    missed_drops = expected_drop - dropped        # validator kept noise (FN)
    wrong_drops = dropped - expected_drop         # validator dropped real bug (FP — worst)
    correct_keeps = expected_keep - dropped       # validator kept a real bug

    rows = []
    for i, entry in enumerate(FIXTURE):
        if entry["_expected_drop"]:
            verdict = "PASS (correctly dropped)" if i in dropped else "FAIL (kept noise)"
        else:
            verdict = "FAIL (dropped real bug)" if i in dropped else "PASS (kept real)"
        rows.append((i, verdict, entry["file"], entry["line"], entry["_why"]))

    print(f"{'#':<3} {'Verdict':<26} {'Where':<50} {'Notes'}")
    print("-" * 130)
    for i, verdict, file, line, why in rows:
        loc = f"{file}:{line}"
        print(f"{i:<3} {verdict:<26} {loc:<50} {why[:60]}")

    print()
    print(f"True-positive  drops (correctly dropped noise): {len(correct_drops)}/{len(expected_drop)}")
    print(f"False-negative drops (noise that slipped through): {len(missed_drops)}")
    print(f"False-positive drops (real bug wrongly dropped): {len(wrong_drops)}  ← worst class")
    print(f"True-negative  keeps (real bugs preserved): {len(correct_keeps)}/{len(expected_keep)}")

    # Pass criterion: zero false-positive drops AND ≥75% of noise caught.
    passed = (len(wrong_drops) == 0
              and len(correct_drops) >= 0.75 * len(expected_drop))
    print(f"\n{'PASS' if passed else 'FAIL'}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
