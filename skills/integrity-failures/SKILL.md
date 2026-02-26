---
name: integrity-failures
description: Use when writing deserialization code, processing pickled or marshalled
  data, implementing software update mechanisms, consuming CI/CD artifact downloads,
  or handling data from untrusted sources that gets reconstructed into objects. Also
  invoke when verifying digital signatures or checksums.
---

# Software and Data Integrity Failures Security Check (A08:2025)

## What this checks

Protects against arbitrary code execution and tampered artifacts. Deserializing untrusted data with `pickle` or unsafe YAML loaders gives attackers remote code execution; unsigned software updates allow supply-chain compromise.

## Vulnerable patterns

- `pickle.loads(request.body)` — executes arbitrary code embedded in pickled payload
- `yaml.load(user_input)` — unsafe loader; runs Python constructors in YAML
- `data = json.loads(body); eval(data["expr"])` — deserializing into executable eval
- `urllib.request.urlretrieve(update_url, "update.bin")` — no signature verification
- Trusting `__reduce__` or `__wakeup` output from user-controlled serialized blobs

## Fix immediately

When this skill invokes, rewrite the vulnerable code using the pattern below. Explain what was wrong and what changed. Then continue with the original task.

**Secure pattern:**

```python
import json
import hashlib
import hmac
import os
import yaml
from jsonschema import validate, ValidationError

# --- Safe deserialization: JSON + schema, never pickle ---
UPDATE_SCHEMA = {
    "type": "object",
    "properties": {
        "version": {"type": "string", "pattern": r"^\d+\.\d+\.\d+$"},
        "payload": {"type": "string"},
    },
    "required": ["version", "payload"],
    "additionalProperties": False,
}

def deserialize_update(raw: bytes) -> dict:
    try:
        data = json.loads(raw)          # never pickle.loads
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid JSON") from exc
    try:
        validate(instance=data, schema=UPDATE_SCHEMA)
    except ValidationError as exc:
        raise ValueError(f"Schema violation: {exc.message}") from exc
    return data

# --- Safe YAML loading ---
def load_config(yaml_str: str) -> dict:
    return yaml.safe_load(yaml_str)     # safe_load disallows Python constructors

# --- Signature verification before trusting any downloaded artifact ---
SIGNING_KEY = os.environb[b"ARTIFACT_HMAC_KEY"]

def verify_artifact(artifact: bytes, provided_sig: str) -> bytes:
    expected = hmac.new(SIGNING_KEY, artifact, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, provided_sig):
        raise ValueError("Artifact signature invalid — refusing to load")
    return artifact
```

**Why this works:** `json.loads` cannot execute code; `yaml.safe_load` disables arbitrary Python constructors; HMAC verification ensures artifacts haven't been tampered with before they are trusted.

## Verification

After rewriting, confirm:

- [ ] No `pickle.loads`, `marshal.loads`, or `shelve` on untrusted input anywhere in the codebase
- [ ] All `yaml.load` calls use `Loader=yaml.SafeLoader` or are replaced with `yaml.safe_load`
- [ ] Deserialized objects are validated against a strict schema before use
- [ ] Software update and CI artifact downloads verify a cryptographic signature before execution
- [ ] Signing keys are stored in environment variables or a secrets manager, not in source

## References

- CWE-502 ([Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html))
- CWE-345 ([Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html))
- [OWASP A08:2025 – Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
