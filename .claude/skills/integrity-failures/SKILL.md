---
name: integrity-failures
description: Use when writing deserialization code, processing pickled or marshalled
  data, implementing software update mechanisms, consuming CI/CD artifact downloads,
  or handling data from untrusted sources that gets reconstructed into objects.
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

After rewriting, confirm the following *properties* hold for every relevant pattern present in the code under review (language-agnostic; criteria apply only to patterns actually present):

- [ ] For every deserialization call present (pickle, marshal, shelve, Java `ObjectInputStream.readObject`, Ruby `Marshal.load`, PHP `unserialize`, .NET `BinaryFormatter`, etc.), the input source is a trusted local constant — never a network payload, request body, file upload, or other attacker-reachable bytes
- [ ] For every YAML load present, the call uses a safe loader (`yaml.safe_load`, `Loader=SafeLoader`, SnakeYAML `SafeConstructor`, etc.) that disallows arbitrary type/constructor instantiation
- [ ] Every deserialized object produced from untrusted input (JSON, YAML, XML, form data, message queue payload) is validated against an explicit schema — field names, types, and allowed values — before any field is read or passed to downstream logic. No untrusted deserialized object reaches business logic unvalidated
- [ ] For every software-update, plugin-load, or CI-artifact download present in the code, the artifact's cryptographic signature or digest is verified against a trusted public key or pinned hash before the artifact is executed, loaded, or written to a trusted path
- [ ] For every signing or verification key referenced in the code, the key material is read from an environment variable, secrets manager, or OS keystore — never hardcoded as a literal in source

## References

- CWE-502 ([Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html))
- CWE-345 ([Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html))
- [OWASP A08:2025 – Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
