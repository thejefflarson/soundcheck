---
name: redos
description: Use when writing regular expressions that will be applied to user-supplied
  input. Also invoke when compiling regexes from external configuration, building input
  validation patterns, or parsing untrusted strings with regex.
---

# ReDoS Security Check (CWE-1333)

## What this checks

Protects against Regular Expression Denial of Service where a crafted input causes
catastrophic backtracking in regex engines. A single malicious string can pin a CPU
core for minutes or hours, taking down the service.

## Vulnerable patterns

- `re.match(r"(a+)+$", user_input)` — nested quantifiers cause exponential backtracking
- `Pattern.compile("(.*a){20}")` — overlapping alternation with repetition
- `/^([\w.]+)+@/ .test(email)` — common email regex with catastrophic backtracking
- `Regex::new(r"(\d+\.?\d*)+")` — ambiguous quantifier nesting on numeric input

## Fix immediately

Flag the vulnerable regex and explain the risk. Show the secure pattern below as a
suggested fix. Then continue with the original task.

**Secure patterns:**

1. **Avoid nested quantifiers** — `(a+)+` → `a+`
2. **Use atomic groups or possessive quantifiers** where supported — `(?>a+)` or `a++`
3. **Set a timeout** on regex execution:

```python
# Python — use re2 or set a match timeout
import re
# Bad: re.match(r"(a+)+$", user_input)
# Good: anchor and simplify
re.match(r"a+$", user_input)
# Or use google-re2 which guarantees linear time
```

```go
// Go — regexp package uses RE2 engine (safe by default)
// Go's regexp CANNOT have catastrophic backtracking
r := regexp.MustCompile(`a+$`)
```

```java
// Java — no built-in protection; simplify or add timeout
Pattern p = Pattern.compile("a+$"); // simplified, no nesting
Matcher m = p.matcher(input);
// For complex patterns, run in a thread with a timeout
```

**Why this works:** Removing nested quantifiers eliminates the exponential state space.
RE2-based engines (Go, google-re2) guarantee linear-time matching by disallowing
backtracking entirely.

## Verification

- [ ] No regex applied to user input contains nested quantifiers like `(a+)+`, `(a*)*`, `(a|a)+`, or `(a+b?)+`
- [ ] Regexes with alternation inside repetition are rewritten to avoid overlap between alternatives
- [ ] If the language supports it (Go, Rust), a linear-time regex engine is used; otherwise patterns are simplified or execution is time-bounded

## References

- CWE-1333 ([Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html))
- CWE-400 ([Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html))
