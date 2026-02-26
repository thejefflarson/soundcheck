---
name: llm-supply-chain
description: Use when writing code that downloads pre-trained models, loads models
  from registries or file paths, integrates third-party LLM providers, or manages
  model version selection. Also invoke when setting up model serving infrastructure
  or automated model updates.
---

# LLM Supply Chain Security Check (OWASP LLM05:2025)

## What this checks

Protects against compromised or backdoored models introduced through unverified
downloads, floating version tags, or unreviewed third-party providers. A tampered
model weight file or a silently swapped `latest` tag can introduce persistent
backdoors that survive retraining.

## Vulnerable patterns

- `model = load("https://arbitrary-host.com/model.bin")` — no checksum verification
- `model_id = "org/model:latest"` — floating tag silently pulls a different artifact on each run
- No review of model card, license, or provenance before integrating a third-party model
- Automated model updates in CI with no human approval gate

## Fix immediately

When this skill invokes, rewrite the vulnerable code using the pattern below. Explain
what was wrong and what changed. Then continue with the original task.

**Secure pattern:**

```python
import hashlib
from pathlib import Path
import requests
from transformers import AutoModelForCausalLM, AutoTokenizer

# Pin exact commit SHA — never use "main" or "latest"
PINNED_MODEL_ID  = "meta-llama/Llama-3.2-1B"
PINNED_REVISION  = "a7c4f09e"          # git commit SHA from the model repository
EXPECTED_SHA256  = "b3d9f1..."          # pre-computed and stored in version control

ALLOWED_ORGS = {"meta-llama", "mistralai", "google", "openai"}

def verify_model_file(path: Path, expected_hex: str) -> None:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != expected_hex:
        raise ValueError(f"Model checksum mismatch: expected {expected_hex}, got {digest}")

def validate_model_source(model_id: str) -> None:
    org = model_id.split("/")[0]
    if org not in ALLOWED_ORGS:
        raise ValueError(f"Model org '{org}' is not in the approved allowlist.")

def load_verified_model(cache_dir: Path):
    validate_model_source(PINNED_MODEL_ID)

    tokenizer = AutoTokenizer.from_pretrained(
        PINNED_MODEL_ID,
        revision=PINNED_REVISION,       # pinned commit; not "main"
        cache_dir=cache_dir,
    )
    model = AutoModelForCausalLM.from_pretrained(
        PINNED_MODEL_ID,
        revision=PINNED_REVISION,
        cache_dir=cache_dir,
    )

    # Verify the cached weight file after download
    weight_file = next(cache_dir.glob("*.safetensors"))
    verify_model_file(weight_file, EXPECTED_SHA256)

    return tokenizer, model
```

**Why this works:** Pinning the revision to a commit SHA guarantees the same artifact
on every pull. The org allowlist blocks models from unvetted sources. Post-download
checksum verification catches tampering that occurs in transit or in the registry cache.

## Verification

After rewriting, confirm:

- [ ] Model IDs specify an exact commit SHA revision, not `"main"` or `"latest"`
- [ ] SHA-256 checksums for model weight files are pinned in version control and verified post-download
- [ ] Model source organization is validated against an approved allowlist
- [ ] Model cards and licenses are reviewed before any new third-party model is integrated
- [ ] CI model-update PRs require manual approval before merging

## References

- CWE-1395 ([Dependency on Vulnerable Third-Party Component](https://cwe.mitre.org/data/definitions/1395.html))
- CWE-494 ([Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html))
- [OWASP LLM05:2025 Supply Chain Vulnerabilities](https://genai.owasp.org/llmrisk/llm05-supply-chain-vulnerabilities/)
