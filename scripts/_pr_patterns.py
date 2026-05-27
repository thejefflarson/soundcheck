"""Deterministic regex pre-pass for the pr-review CI gate.

This is Layer 1 of the iterative-review case. The LLM (Layer 2) handles
context-dependent issues — IDOR, auth bypass, cross-file dataflow,
anything regex can't decide alone. This module handles the cases that
need no judgment: a hit means a real bug, full stop.

Inclusion bar is conservative. A pattern lives here only if:

  1. There is no safe form of the matched expression. (`yaml.load(...)`
     is always wrong on untrusted bytes; `yaml.safe_load(...)` is the
     fix — different name, no regex collision.)
  2. The match doesn't require surrounding context to classify.
  3. It maps to an existing Soundcheck skill so the finding has a
     consistent category label.

If you can think of a legitimate use of the matched expression in
production code, the pattern does not belong here. Move it to the
LLM pass (where context determines verdict) instead of expanding this
catalog into noise.
"""

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Pattern:
    """A single regex rule."""
    regex: re.Pattern
    exts: tuple[str, ...]    # file extensions where this rule applies
    skill: str               # corresponding Soundcheck skill
    severity: str            # Critical / High / Medium / Low
    finding: str             # one-sentence description for the report
    fix: str                 # one-sentence remediation hint


def _p(regex: str, exts: tuple[str, ...], skill: str, severity: str,
       finding: str, fix: str) -> Pattern:
    return Pattern(
        regex=re.compile(regex, re.MULTILINE),
        exts=exts, skill=skill, severity=severity,
        finding=finding, fix=fix,
    )


# Curated patterns — see module docstring for inclusion bar.
PATTERNS: tuple[Pattern, ...] = (
    _p(
        r"\byaml\.load\s*\(",
        (".py",), "integrity-failures", "High",
        "yaml.load() executes arbitrary Python via tag constructors when "
        "given untrusted YAML — equivalent to pickle.loads on a string.",
        "Replace with yaml.safe_load(), which uses the SafeLoader and "
        "refuses Python object tags.",
    ),
    _p(
        r"\bpickle\.loads?\s*\(",
        (".py",), "integrity-failures", "High",
        "pickle.load / pickle.loads executes arbitrary code on deserialization "
        "and must never be called on attacker-influenced bytes.",
        "Switch to a safe format: JSON for simple data, protobuf or "
        "msgpack with a schema for structured data.",
    ),
    _p(
        r"subprocess\.\w+\([^)]*shell\s*=\s*True",
        (".py",), "injection", "High",
        "subprocess call with shell=True passes the command to a shell, "
        "enabling shell injection if any argument is attacker-influenced.",
        "Remove shell=True and pass the command as a list of args: "
        'subprocess.run(["ls", "-l", path]).',
    ),
    _p(
        r"requests\.\w+\([^)]*verify\s*=\s*False",
        (".py",), "cryptographic-failures", "Medium",
        "TLS verification disabled on an outbound HTTPS request — strips "
        "the security guarantee, enabling MITM.",
        "Remove verify=False (or set verify=True). If the server uses a "
        "private CA, set verify=/path/to/ca-bundle.pem instead.",
    ),
    _p(
        r'algorithms\s*=\s*\[\s*[\'"]none[\'"]',
        (".py", ".js", ".ts", ".mjs"), "authentication-failures", "Critical",
        'JWT verification accepts the "none" algorithm — any unsigned '
        "token passes signature check, allowing full auth bypass.",
        'Pin to an explicit signing algorithm: algorithms=["HS256"] or '
        '["RS256"], never "none".',
    ),
    _p(
        r"\bdangerouslySetInnerHTML\b",
        (".js", ".jsx", ".ts", ".tsx", ".mjs"), "injection", "High",
        "dangerouslySetInnerHTML inserts a raw HTML string into the DOM, "
        "bypassing React's XSS protection.",
        "Render the value as a string child of an element, or sanitize "
        "with DOMPurify before inserting.",
    ),
    _p(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----",
        (".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".kt",
         ".rb", ".c", ".cpp", ".cs", ".yml", ".yaml", ".json", ".toml",
         ".env", ".pem", ".key"),
        "hardcoded-secrets", "Critical",
        "Private key material committed to source — anyone with read access "
        "to this branch can impersonate the key holder.",
        "Move the key to a secrets manager (Vault / AWS Secrets Manager / "
        "1Password) and load it from the environment at runtime.",
    ),
    _p(
        r"AKIA[A-Z0-9]{16}",
        (".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".kt",
         ".rb", ".c", ".cpp", ".cs", ".yml", ".yaml", ".json", ".toml",
         ".env", ".sh"),
        "hardcoded-secrets", "Critical",
        "AWS Access Key ID hardcoded in source — rotate immediately and "
        "audit CloudTrail for unauthorized use.",
        "Move credentials to environment variables or IAM roles. Add the "
        "leaked key to your secret-rotation runbook.",
    ),
)


def scan_files(repo_dir: Path, paths: list[str]) -> list[dict]:
    """Scan the given files for matches against PATTERNS.

    Returns a list of finding dicts in the Soundcheck schema:
    {severity, file, line, skill, finding, fix}. Paths are repo-
    relative; the caller supplies repo_dir for resolution.
    """
    findings: list[dict] = []
    for rel in paths:
        ext = "".join(Path(rel).suffixes[-1:]) or Path(rel).suffix
        applicable = [p for p in PATTERNS if ext in p.exts]
        if not applicable:
            continue
        try:
            text = (repo_dir / rel).read_text(encoding="utf-8", errors="ignore")
        except (FileNotFoundError, IsADirectoryError, PermissionError):
            continue
        for pat in applicable:
            for match in pat.regex.finditer(text):
                line = text[:match.start()].count("\n") + 1
                findings.append({
                    "severity": pat.severity,
                    "file": rel,
                    "line": line,
                    "skill": pat.skill,
                    "finding": pat.finding,
                    "fix": pat.fix,
                })
    # Dedupe by (file, line, skill) — multiple regex matches on the same
    # line for the same skill collapse to one finding.
    seen: set[tuple[str, int, str]] = set()
    deduped: list[dict] = []
    for f in findings:
        key = (f["file"], f["line"], f["skill"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    return deduped
