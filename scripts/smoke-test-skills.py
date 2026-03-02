#!/usr/bin/env python3
"""
API smoke tests for Soundcheck skill test cases.

Sends each test case to the Claude API and asserts that the response identifies
the expected vulnerability type. Uses claude-haiku-4-5 to keep costs low.

Usage:
    python scripts/smoke-test-skills.py
    python scripts/smoke-test-skills.py --skill injection
    python scripts/smoke-test-skills.py --verbose
    python scripts/smoke-test-skills.py --fail-fast

Cost estimate: ~20 calls × ~500 tokens each ≈ $0.10–0.30 per full run
"""

import argparse
import os
import sys
import time
from pathlib import Path

import anthropic

ROOT = Path(__file__).parent.parent

MODEL = "claude-haiku-4-5"

PROMPT = (
    "Identify all security vulnerabilities in this code. "
    "Be specific about vulnerability types."
)

# Expected keywords per skill (case-insensitive, any match = pass)
EXPECTED_KEYWORDS: dict[str, list[str]] = {
    "injection": [
        "sql injection",
        "command injection",
        "shell injection",
        "template injection",
        "code injection",
    ],
    "broken-access-control": [
        "access control",
        "authorization",
        "ssrf",
        "privilege escalation",
        "idor",
    ],
    "cryptographic-failures": [
        "md5",
        "weak",
        "bcrypt",
        "aes",
        "random",
        "cryptograph",
        "hash",
    ],
    "authentication-failures": [
        "password",
        "hash",
        "bcrypt",
        "jwt",
        "session",
        "hardcoded",
        "credential",
        "brute force",
    ],
    "insecure-design": [
        "rate limit",
        "lockout",
        "re-authentication",
        "business logic",
        "brute force",
    ],
    "security-misconfiguration": [
        "cors",
        "debug",
        "default",
        "header",
        "misconfiguration",
        "secret key",
    ],
    "supply-chain": [
        "dependency",
        "version",
        "lockfile",
        "checksum",
        "supply chain",
        "package",
        "curl",
        "pipe",
    ],
    "integrity-failures": [
        "pickle",
        "deserializ",
        "yaml",
        "signature",
        "marshal",
        "unsafe",
    ],
    "logging-failures": [
        "log",
        "crlf",
        "password",
        "sensitive",
        "audit",
        "injection",
    ],
    "exceptional-conditions": [
        "stack trace",
        "error disclosure",
        "exception",
        "sensitive",
        "information leakage",
        "error handling",
    ],
    "prompt-injection": [
        "prompt injection",
        "indirect injection",
        "user input",
        "instruction",
    ],
    "insecure-output-handling": [
        "xss",
        "cross-site scripting",
        "innerhtml",
        "injection",
        "sanitiz",
        "escape",
    ],
    "training-data-poisoning": [
        "poison",
        "dataset",
        "label",
        "validation",
        "checksum",
        "manipulation",
    ],
    "model-dos": [
        "denial of service",
        "resource",
        "max_tokens",
        "rate limit",
        "input",
        "exhaustion",
        "dos",
    ],
    "llm-supply-chain": [
        "model",
        "checksum",
        "pin",
        "hash",
        "supply chain",
        "version",
        "huggingface",
    ],
    "sensitive-disclosure": [
        "sensitive",
        "pii",
        "personal",
        "credential",
        "leak",
        "disclose",
        "privacy",
    ],
    "insecure-plugin-design": [
        "path traversal",
        "injection",
        "validation",
        "authorization",
        "input",
    ],
    "excessive-agency": [
        "permission",
        "privilege",
        "agency",
        "action",
        "irreversible",
        "approval",
        "execute",
    ],
    "overreliance": [
        "hallucination",
        "verification",
        "review",
        "reliance",
        "disclaimer",
        "confidence",
        "trust",
        "validate",
    ],
    "model-theft": [
        "rate limit",
        "extraction",
        "api",
        "quota",
        "theft",
        "model",
        "unauthorized",
    ],
    "mcp-security": [
        "path traversal",
        "shell injection",
        "hardcoded",
        "command injection",
        "secret",
        "input validation",
        "schema",
    ],
    "oauth-implementation": [
        "redirect",
        "jwt",
        "algorithm",
        "csrf",
        "state",
        "open redirect",
        "authentication",
    ],
    "rag-security": [
        "prompt injection",
        "ssrf",
        "allowlist",
        "retrieval",
        "injection",
        "url",
        "context",
    ],
    "threat-modeling": [
        "authentication",
        "authorization",
        "rate limit",
        "encryption",
        "trust boundary",
        "threat",
        "access control",
    ],
    "security-review": [
        "sql injection",
        "command injection",
        "md5",
        "plaintext",
        "password",
        "credentials",
        "logging",
        "exception",
    ],
}


def find_test_case(skill_name: str) -> Path | None:
    """Find the test case file for a skill."""
    test_dir = ROOT / "docs" / "test-cases"
    matches = list(test_dir.glob(f"{skill_name}.*"))
    return matches[0] if matches else None


def run_smoke_test(
    client: anthropic.Anthropic,
    skill_name: str,
    verbose: bool = False,
) -> tuple[bool, str]:
    """
    Run a single smoke test.

    Returns (passed, detail_message).
    """
    test_case = find_test_case(skill_name)
    if test_case is None:
        return False, f"No test case found for {skill_name!r}"

    keywords = EXPECTED_KEYWORDS.get(skill_name)
    if keywords is None:
        return False, f"No expected keywords defined for {skill_name!r}"

    code = test_case.read_text(encoding="utf-8")

    max_retries = 5
    for attempt in range(max_retries):
        try:
            response = client.messages.create(
                model=MODEL,
                max_tokens=1024,
                messages=[
                    {
                        "role": "user",
                        "content": f"{PROMPT}\n\n```\n{code}\n```",
                    }
                ],
            )
            break
        except anthropic.APIStatusError as exc:
            if exc.status_code == 529 and attempt < max_retries - 1:
                wait = 2 ** attempt
                print(f"  [overloaded, retrying in {wait}s]", flush=True)
                time.sleep(wait)
            else:
                raise

    response_text = response.content[0].text.lower()

    if verbose:
        print(f"\n--- Claude response for {skill_name} ---")
        print(response.content[0].text)
        print("---")

    matched = [kw for kw in keywords if kw.lower() in response_text]
    if matched:
        return True, f"matched: {matched[0]!r}"
    else:
        return False, f"no keyword matched (expected one of: {keywords})"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Smoke test Soundcheck skill detection via Claude API"
    )
    parser.add_argument("--skill", metavar="NAME", help="Test a single skill by name")
    parser.add_argument(
        "--verbose", action="store_true", help="Print full Claude responses"
    )
    parser.add_argument(
        "--fail-fast", action="store_true", help="Stop on first failure"
    )
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY environment variable not set", file=sys.stderr)
        return 1

    client = anthropic.Anthropic(api_key=api_key)

    if args.skill:
        skill_names = [args.skill]
    else:
        skill_names = sorted(EXPECTED_KEYWORDS.keys())

    pass_count = 0
    fail_count = 0
    col_width = max(len(n) for n in skill_names) + 2

    print(f"\nSoundcheck Smoke Tests — {len(skill_names)} skill(s) — model: {MODEL}\n")
    print(f"{'Skill':<{col_width}} {'Status':<8}  Detail")
    print("-" * 72)

    for i, skill_name in enumerate(skill_names):
        if i > 0:
            time.sleep(1)
        try:
            passed, detail = run_smoke_test(client, skill_name, verbose=args.verbose)
        except anthropic.APIError as exc:
            passed, detail = False, f"API error: {exc}"

        status = "PASS" if passed else "FAIL"
        print(f"{skill_name:<{col_width}} {status:<8}  {detail}")

        if passed:
            pass_count += 1
        else:
            fail_count += 1
            if args.fail_fast:
                print("\nStopping on first failure (--fail-fast)")
                break

    print("-" * 72)
    print(f"\nResults: {pass_count} passed, {fail_count} failed\n")

    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
