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

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **Any recursive merge, clone, or property copy on user input filters the
   dangerous keys** — `__proto__`, `constructor`, `prototype`. The filter runs
   before assignment, not after; a post-hoc `delete obj.__proto__` doesn't help
   because the prototype chain was already mutated.
2. **Dynamic property assignment (`obj[userKey] = value`) validates the key
   against a blocklist**, or sidesteps the issue by using a `Map` instead. A
   `Map` has no prototype chain exposure; `obj[userKey]` does.
3. **Config and lookup objects use `Object.create(null)` when keys come from
   input.** A null-prototype object cannot be polluted because there is no
   prototype chain to reach.
4. **Lodash `_.merge`, `_.set`, and jQuery `$.extend(true, …)` on untrusted
   input are replaced** with key-filtered wrappers or safe alternatives. The
   issue is library-version-dependent, so relying on patched versions is
   fragile; filter at the call site.

Anchor — shape, not implementation:

```
const BAD = new Set(["__proto__", "constructor", "prototype"]);
function safeMerge(t, s) {
  for (const k of Object.keys(s)) {          // not `for ... in`
    if (BAD.has(k)) continue;
    t[k] = (isObj(s[k]) && isObj(t[k])) ? safeMerge(t[k], s[k]) : s[k];
  }
  return t;
}
// or: const config = Object.create(null);   // no prototype to pollute
```

## Verification

- [ ] No deep merge, clone, or recursive property copy on user-controlled input proceeds without filtering `__proto__`, `constructor`, and `prototype` keys
- [ ] Dynamic property assignment from user input (`obj[userKey] = value`) validates the key against a blocklist or uses `Map` instead
- [ ] If lodash is used, `_.merge` on untrusted input is replaced with a safe alternative or key-filtered wrapper

## References

- CWE-1321 ([Improperly Controlled Modification of Object Prototype Attributes](https://cwe.mitre.org/data/definitions/1321.html))
