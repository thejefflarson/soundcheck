---
name: integrity-failures
description: Use when writing deserialization code, processing pickled or marshalled
  data, implementing software update mechanisms, consuming CI/CD artifact downloads,
  or handling data from untrusted sources that gets reconstructed into objects.
---

# Software and Data Integrity Failures Security Check (A08:2025)

## What this checks

Protects against arbitrary code execution and tampered artifacts. Deserializing
untrusted data with `pickle` or unsafe YAML loaders gives attackers remote code
execution; unsigned software updates allow supply-chain compromise.

## Vulnerable patterns

- `pickle.loads(request.body)` — executes arbitrary code embedded in pickled payload
- `yaml.load(user_input)` — unsafe loader; runs Python constructors in YAML
- `data = json.loads(body); eval(data["expr"])` — deserializing into executable eval
- `urllib.request.urlretrieve(update_url, "update.bin")` — no signature verification
- Trusting `__reduce__` or `__wakeup` output from user-controlled serialized blobs
- JSON/YAML deserialized and returned to callers with no field-level schema check

## Fix immediately

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **No code-executing deserializer touches untrusted input.** Replace `pickle`,
   `marshal`, `shelve`, Java `ObjectInputStream`, Ruby `Marshal.load`, PHP
   `unserialize`, .NET `BinaryFormatter`, and unsafe `yaml.load` with a
   data-only format: JSON, `yaml.safe_load`, protobuf, CBOR without tags.
2. **Every deserialized object from untrusted input is validated against an
   explicit schema** — field names, types, allowed values — before any field is
   read by business logic. Applies to JSON, YAML, XML, form bodies, message-queue
   payloads, binary bincode/msgpack; format doesn't matter.
3. **Artifacts are signature- or digest-verified before trust.** Software updates,
   plugin loads, CI-artifact downloads: check a cryptographic signature against a
   trusted public key, or a digest against a pinned hash, before executing or
   loading.
4. **Keys and pinned hashes come from outside the source tree** — environment
   variable, secrets manager, OS keystore, or a build-time constant baked into
   the binary. A value received as a function parameter with no visible origin
   does not demonstrate this.

Anchor — shape, not implementation:

```
data = json_load(untrusted_bytes)          # never pickle/marshal/yaml.load
validate(data, schema=EXPLICIT_SCHEMA)     # reject unknown fields and bad types
use(data)                                  # safe only after validation
```

## Verification

Confirm these properties hold for every relevant pattern present:

- [ ] No code-executing deserializer (pickle, marshal, shelve, `ObjectInputStream.readObject`, `Marshal.load`, `unserialize`, `BinaryFormatter`, unsafe `yaml.load`) receives attacker-reachable bytes. Safe formats (JSON, `yaml.safe_load`, protobuf) may accept untrusted input if the next criterion is met.
- [ ] Every deserialized object produced from untrusted input is validated against an explicit schema — field names, types, allowed values — before any field reaches business logic
- [ ] For every software-update, plugin-load, or CI-artifact download, the artifact's signature or digest is verified before it is executed, loaded, or written to a trusted path
- [ ] Verification keys and pinned hashes are read from an environment variable, secrets manager, OS keystore, or build-time constant — not hardcoded literals in source, and not opaque function parameters

## References

- CWE-502 ([Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html))
- CWE-345 ([Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html))
- [OWASP A08:2025 – Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
