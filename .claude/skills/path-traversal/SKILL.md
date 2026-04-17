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

Flag the vulnerable code and explain the risk. Show the secure pattern below as a
suggested fix. Then continue with the original task.

**Secure pattern:**

```python
# Python — resolve and verify containment
from pathlib import Path

UPLOAD_DIR = Path("/app/uploads").resolve()

def safe_read(filename: str) -> bytes:
    target = (UPLOAD_DIR / filename).resolve()
    if not target.is_relative_to(UPLOAD_DIR):
        raise ValueError("Path traversal blocked")
    return target.read_bytes()
```

```go
// Go — Clean + verify prefix
func safeRead(root, userPath string) ([]byte, error) {
    absRoot, _ := filepath.Abs(root)
    target := filepath.Join(absRoot, filepath.Clean("/"+userPath))
    if !strings.HasPrefix(target, absRoot+string(os.PathSeparator)) {
        return nil, fmt.Errorf("path traversal blocked")
    }
    // Also reject symlinks that escape
    real, err := filepath.EvalSymlinks(target)
    if err != nil { return nil, err }
    if !strings.HasPrefix(real, absRoot+string(os.PathSeparator)) {
        return nil, fmt.Errorf("symlink escape blocked")
    }
    return os.ReadFile(real)
}
```

```java
// Java — toRealPath resolves symlinks and normalizes
Path root = Paths.get("/app/uploads").toRealPath();
Path target = root.resolve(userInput).toRealPath();
if (!target.startsWith(root)) {
    throw new SecurityException("Path traversal blocked");
}
```

**Why this works:** Resolving to an absolute canonical path collapses all `..` segments
and follows symlinks. The containment check then verifies the result is still under the
intended root. This blocks `../`, absolute paths, and symlink escapes.

## Verification

- [ ] Every file operation using a caller-supplied path or filename resolves to a canonical absolute path and verifies it starts with the intended root directory
- [ ] Symlinks are resolved (via realpath/EvalSymlinks/toRealPath) before the containment check, blocking symlink escapes
- [ ] User-supplied filenames are never concatenated or interpolated into paths without canonicalization — `os.path.join` and `filepath.Join` alone are NOT sufficient
- [ ] The root directory itself is resolved to a canonical path before comparison

## References

- CWE-22 ([Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html))
- CWE-59 ([Improper Link Resolution Before File Access](https://cwe.mitre.org/data/definitions/59.html))
- [OWASP A01:2025 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
