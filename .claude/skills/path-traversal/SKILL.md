---
name: path-traversal
description: Use when writing code that opens, reads, writes, or deletes files using
  paths constructed from user input. Also invoke when serving static files, handling
  file downloads by name, or resolving paths from URL parameters or request bodies.
---

# Path Traversal Security Check (A01:2025)

## What this checks

Protects against directory traversal attacks where an attacker uses `../` sequences,
absolute paths, or symlinks to access files outside the intended directory. Exploitation
leads to reading sensitive files (`/etc/passwd`, `.env`, private keys), overwriting
configuration, or achieving remote code execution via file write.

## Vulnerable patterns

- `open(f"/uploads/{filename}")` — user-supplied filename can contain `../../etc/passwd`
- `os.path.join(base, user_input)` — join does NOT prevent absolute paths (`/etc/passwd` ignores base)
- `filepath.Join(root, r.URL.Query().Get("file"))` — Go join strips `..` but doesn't verify result is under root
- `Paths.get(baseDir, userInput)` — Java Path doesn't enforce containment
- `fs::read_to_string(format!("data/{}", user_input))` — format string allows traversal

## Fix immediately

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **The intended root is resolved to a canonical absolute path once**, up
   front. Everything that follows compares against the resolved root — not
   against a relative string that can match itself after traversal.
2. **The caller-supplied path is joined with the root, then resolved to a
   canonical absolute path that also follows symlinks.** `realpath`,
   `Path.resolve()`, `toRealPath()`, `filepath.EvalSymlinks` — the call that
   collapses `../` and follows links. Only after this does the containment
   check make sense.
3. **The resolved target must start with the resolved root** (or
   `is_relative_to`, `startsWith` equivalent). A mismatch means traversal or
   symlink escape; reject rather than fall through. `os.path.join` and
   `filepath.Join` alone do not satisfy this — they collapse some `..` but
   don't verify containment.
4. **The check runs before every file operation** — read, write, delete, stat.
   A canonicalization that happens once at handler entry but isn't re-applied
   to a later `open()` call is a bug.

Anchor — shape, not implementation:

```
root   = canonical(ROOT_DIR)
target = canonical(root / user_filename)           # resolves .., follows symlinks
require(target.starts_with(root))                  # containment
open(target)
```

## Verification

- [ ] Every file operation using a caller-supplied path or filename resolves to a canonical absolute path and verifies it starts with the intended root directory
- [ ] Symlinks are resolved (via realpath/EvalSymlinks/toRealPath) before the containment check, blocking symlink escapes
- [ ] User-supplied filenames are never concatenated or interpolated into paths without canonicalization — `os.path.join` and `filepath.Join` alone are NOT sufficient
- [ ] The root directory itself is resolved to a canonical path before comparison

## References

- CWE-22 ([Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html))
- CWE-59 ([Improper Link Resolution Before File Access](https://cwe.mitre.org/data/definitions/59.html))
- [OWASP A01:2025 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
