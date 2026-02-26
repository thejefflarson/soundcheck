---
name: training-data-poisoning
description: Use when writing fine-tuning pipelines, dataset ingestion scripts, external
  training data loaders, or code that collects and processes data for model training.
  Also invoke when automating dataset curation from web scraping or user-contributed
  sources.
---

# Training Data Poisoning Security Check (OWASP LLM03:2025)

## What this checks

Protects against malicious or low-quality examples being introduced into training or
fine-tuning datasets. Poisoned data can embed backdoors, degrade accuracy, or skew
model behavior in ways that are difficult to detect after training completes.

## Vulnerable patterns

- Ingesting scraped or user-contributed examples with no content validation
- No deduplication or anomaly detection on training set statistics
- Loading dataset files without verifying provenance or checksums
- Using the same split for training and validation, hiding distribution shift

## Fix immediately

When this skill invokes, rewrite the vulnerable code using the pattern below. Explain
what was wrong and what changed. Then continue with the original task.

**Secure pattern:**

```python
import hashlib, json, re
from pathlib import Path
from collections import Counter

KNOWN_DATASET_HASHES: dict[str, str] = {
    "training_v3.jsonl": "sha256:a3f1c8...",   # pre-computed, stored in version control
}

def verify_dataset_integrity(path: Path) -> None:
    """Reject files whose checksum does not match the pinned value."""
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = KNOWN_DATASET_HASHES.get(path.name, "").removeprefix("sha256:")
    if not expected or digest != expected:
        raise ValueError(f"Checksum mismatch for {path.name}: got {digest}")

MAX_CHARS = 4096
DISALLOWED = re.compile(r"(ignore previous|jailbreak|<\|.*?\|>)", re.I)

def validate_example(example: dict) -> bool:
    text = example.get("text", "")
    if not isinstance(text, str) or not text.strip():
        return False
    if len(text) > MAX_CHARS:
        return False
    if DISALLOWED.search(text):
        return False
    return True

def load_dataset(path: Path, val_fraction: float = 0.1) -> tuple[list, list]:
    verify_dataset_integrity(path)
    raw = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    # Deduplicate by content hash
    seen: set[str] = set()
    unique = []
    for ex in raw:
        h = hashlib.md5(ex.get("text", "").encode()).hexdigest()
        if h not in seen and validate_example(ex):
            seen.add(h)
            unique.append(ex)

    # Detect label distribution anomalies
    labels = Counter(ex.get("label") for ex in unique)
    total = len(unique)
    for label, count in labels.items():
        if count / total > 0.8:
            raise ValueError(f"Label '{label}' is {count/total:.0%} of dataset — possible poisoning")

    split = int(len(unique) * (1 - val_fraction))
    return unique[:split], unique[split:]   # separate train / validation splits
```

**Why this works:** Checksum verification blocks tampered dataset files. Per-example
validation rejects injected instruction tokens and oversized entries. Deduplication and
label-distribution checks surface statistical anomalies that indicate batch poisoning.

## Verification

After rewriting, confirm:

- [ ] Dataset files are verified against pinned checksums before loading
- [ ] Every training example passes schema and content validation
- [ ] Duplicates are removed before training starts
- [ ] Train and validation splits are kept strictly separate
- [ ] Label/class distribution is checked and alerted on imbalance above a threshold

## References

- CWE-20 ([Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html))
- CWE-1021 ([Improper Restriction of Rendered UI Layers](https://cwe.mitre.org/data/definitions/1021.html))
- [OWASP LLM03:2025 Training Data Poisoning](https://genai.owasp.org/llmrisk/llm03-training-data-poisoning/)
