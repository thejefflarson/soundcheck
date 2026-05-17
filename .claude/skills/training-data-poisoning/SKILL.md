---
name: training-data-poisoning
description: Detects training and fine-tuning pipelines that ingest external data without
  integrity gating. Use when writing fine-tuning pipelines, dataset ingestion
  scripts, external training data loaders, or code that collects and processes
  data for model training. Also invoke when automating dataset curation from
  web scraping or user-contributed sources.
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

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **Every external dataset file is checksum-verified before use.** A pinned
   SHA-256 in version control; the loader computes the digest on load and
   refuses to proceed on mismatch. Pinning a URL or version alone doesn't help
   when the bytes behind them change.
2. **Every example passes content validation** before entering the training
   set: type and length checks, disallowed-pattern filtering (injection tokens
   like `ignore previous`, `<|im_start|>`, jailbreak signatures), and
   encoding/Unicode sanity. Invalid examples are dropped, not silently used.
3. **Duplicates are removed before training.** Poisoning attacks often batch
   the same backdoor trigger across many examples; deduplication by content
   hash limits the leverage of a single injected payload.
4. **Label distribution is checked and alerts fire on imbalance** above a
   threshold. A sudden 80%-one-class shift is a statistical signature of
   bulk-inserted poison; it's cheap to catch at ingestion and impossible to
   reverse after training.
5. **Train and validation splits come from disjoint sources or time windows.**
   Reusing the same split for both hides distribution shift and lets poisoned
   examples score well on validation.

Anchor — shape, not implementation:

```
require(sha256(dataset_file) == PINNED_SHA256)
rows    = [r for r in parse(dataset_file) if validate(r)]        # per-example
unique  = dedupe_by_hash(rows)
require(max_class_fraction(unique) < 0.8)                         # anomaly gate
train, val = split_by_source(unique, val_fraction=0.1)
```

## Verification

Confirm the response:

- [ ] For every external dataset load present, files are verified against pinned checksums before use
- [ ] Every training example passes content validation (length limits, disallowed-pattern filtering)
- [ ] Duplicates are removed before training starts
- [ ] For every dataset with categorical labels present, class distribution is checked and alerted on imbalance above a threshold

## References

- CWE-20 ([Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html))
- CWE-1021 ([Improper Restriction of Rendered UI Layers](https://cwe.mitre.org/data/definitions/1021.html))
- [OWASP LLM03:2025 Training Data Poisoning](https://genai.owasp.org/llmrisk/llm03-training-data-poisoning/)
