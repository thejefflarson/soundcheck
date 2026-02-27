#!/usr/bin/env python3
"""
Static validator for Soundcheck skill files.

Checks every skills/*/SKILL.md against the authoring rules defined in CLAUDE.md.
Exit code 0 = all skills pass. Non-zero = at least one violation found.

Usage:
    python scripts/validate-skills.py
    python scripts/validate-skills.py --skill injection
"""

import argparse
import glob
import re
import sys
from pathlib import Path

# Project root is one level up from this script
ROOT = Path(__file__).parent.parent

REQUIRED_SECTIONS = [
    "## What this checks",
    "## Vulnerable patterns",
    "## Fix immediately",
    "## Verification",
    "## References",
]

OWASP_PATTERN = re.compile(r"(A\d{2}:\d{4}|LLM\d{2}:\d{4})")
CWE_PATTERN = re.compile(r"CWE-\d+")
MAX_WORDS = 400


def parse_frontmatter(text: str) -> dict:
    """Extract YAML-style frontmatter fields from the skill file."""
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end == -1:
        return {}
    fm_block = text[3:end].strip()
    fields: dict = {}
    # Simple key: value parser (handles multi-line values via indentation)
    current_key = None
    current_val_lines = []
    for line in fm_block.splitlines():
        if line and not line[0].isspace() and ":" in line:
            if current_key:
                fields[current_key] = " ".join(current_val_lines).strip()
            key, _, val = line.partition(":")
            current_key = key.strip()
            current_val_lines = [val.strip()]
        elif current_key:
            current_val_lines.append(line.strip())
    if current_key:
        fields[current_key] = " ".join(current_val_lines).strip()
    return fields


def count_words(text: str) -> int:
    """Count words, excluding frontmatter delimiters."""
    # Strip frontmatter
    body = text
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            body = text[end + 4:]
    return len(body.split())


def validate_skill(skill_dir: Path) -> list[str]:
    """Validate a single skill directory. Returns a list of violation strings."""
    skill_file = skill_dir / "SKILL.md"
    violations: list[str] = []

    if not skill_file.exists():
        return [f"SKILL.md not found in {skill_dir}"]

    text = skill_file.read_text(encoding="utf-8")
    name = skill_dir.name

    # 1. Frontmatter: name and description present and non-empty
    fm = parse_frontmatter(text)
    if not fm.get("name", "").strip():
        violations.append("Frontmatter: missing or empty 'name' field")
    if not fm.get("description", "").strip():
        violations.append("Frontmatter: missing or empty 'description' field")

    # 2. No TODO placeholders
    if "TODO" in text:
        violations.append("Contains TODO placeholder(s)")

    # 3. Word count <= 400
    word_count = count_words(text)
    if word_count > MAX_WORDS:
        violations.append(f"Word count {word_count} exceeds {MAX_WORDS} limit")

    # 4. Required sections present
    for section in REQUIRED_SECTIONS:
        if section not in text:
            violations.append(f"Missing required section: {section!r}")

    # 5. At least one CWE reference
    if not CWE_PATTERN.search(text):
        violations.append("No CWE reference found (expected pattern: CWE-\\d+)")

    # 6. OWASP identifier in title
    if not OWASP_PATTERN.search(text):
        violations.append(
            "No OWASP identifier found in title (expected A##:#### or LLM##:####)"
        )

    # 7. Test case file exists
    test_cases = list((ROOT / "docs" / "test-cases").glob(f"{name}.*"))
    if not test_cases:
        violations.append(
            f"No test case found at docs/test-cases/{name}.*"
        )

    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Soundcheck skill files")
    parser.add_argument(
        "--skill",
        metavar="NAME",
        help="Validate a single skill by name (e.g., injection)",
    )
    args = parser.parse_args()

    skills_root = ROOT / "skills"

    if args.skill:
        skill_dirs = [skills_root / args.skill]
        if not skill_dirs[0].is_dir():
            print(f"ERROR: skill directory not found: {skill_dirs[0]}", file=sys.stderr)
            return 1
    else:
        skill_dirs = sorted(
            d for d in skills_root.iterdir() if d.is_dir()
        )

    if not skill_dirs:
        print("ERROR: no skill directories found under skills/", file=sys.stderr)
        return 1

    pass_count = 0
    fail_count = 0
    results: list[tuple[str, list[str]]] = []

    for skill_dir in skill_dirs:
        violations = validate_skill(skill_dir)
        results.append((skill_dir.name, violations))
        if violations:
            fail_count += 1
        else:
            pass_count += 1

    # --- Print results ---
    col_width = max(len(name) for name, _ in results) + 2

    print(f"\nSoundcheck Skill Validation — {len(results)} skills checked\n")
    print(f"{'Skill':<{col_width}} {'Status':<8}  Violations")
    print("-" * 72)

    for name, violations in results:
        status = "PASS" if not violations else "FAIL"
        if violations:
            print(f"{name:<{col_width}} {status}")
            for v in violations:
                print(f"  {'':>{col_width - 2}}  • {v}")
        else:
            print(f"{name:<{col_width}} {status}")

    print("-" * 72)
    print(f"\nResults: {pass_count} passed, {fail_count} failed\n")

    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
