---
name: prototype-pollution
description: Use when writing JavaScript or TypeScript code that deep-merges, clones,
  or extends objects using user-controlled input. Also invoke when using lodash merge/set,
  Object.assign with dynamic keys, or recursive property copy on untrusted data.
---

# Prototype Pollution Security Check (CWE-1321)

## What this checks

Protects against prototype pollution in JavaScript/TypeScript where an attacker injects
properties like `__proto__` or `constructor.prototype` through user input, modifying
the prototype chain of all objects. Exploitation leads to property injection, auth
bypass, and remote code execution in some frameworks.

## Vulnerable patterns

- `_.merge(config, userInput)` — lodash merge recurses into `__proto__`
- `Object.assign(target, JSON.parse(body))` — copies `__proto__` key if present
- `function deepMerge(t, s) { for (k in s) t[k] = ... }` — custom merge without key filter
- `obj[req.body.key] = req.body.value` — dynamic property set on arbitrary key

## Fix immediately

Flag the vulnerable code and explain the risk. Show the secure pattern below as a
suggested fix. Then continue with the original task.

**Secure pattern:**

```javascript
// Block dangerous keys in any merge/set operation
const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function safeMerge(target, source) {
  for (const key of Object.keys(source)) { // Object.keys skips inherited
    if (DANGEROUS_KEYS.has(key)) continue;
    if (typeof source[key] === "object" && source[key] !== null
        && typeof target[key] === "object") {
      safeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Or: use Object.create(null) for config objects (no prototype)
const config = Object.create(null);

// Or: use Map instead of plain objects for dynamic keys
const settings = new Map();
settings.set(userKey, userValue); // Map has no prototype chain risk
```

**Why this works:** Filtering `__proto__`, `constructor`, and `prototype` keys prevents
attackers from reaching the prototype chain. `Object.create(null)` creates objects with
no prototype, making pollution impossible. `Map` avoids the problem entirely.

## Verification

- [ ] No deep merge, clone, or recursive property copy on user-controlled input proceeds without filtering `__proto__`, `constructor`, and `prototype` keys
- [ ] Dynamic property assignment from user input (`obj[userKey] = value`) validates the key against a blocklist or uses `Map` instead
- [ ] If lodash is used, `_.merge` on untrusted input is replaced with a safe alternative or key-filtered wrapper

## References

- CWE-1321 ([Improperly Controlled Modification of Object Prototype Attributes](https://cwe.mitre.org/data/definitions/1321.html))
