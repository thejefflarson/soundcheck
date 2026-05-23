---
name: memory-api-misuse
description: Detects function-local misuse of memory and resource APIs in C, C++, and Rust unsafe — allocations whose return value is not checked, frees on error paths that race the success path, locks initialized incorrectly, file descriptors leaked across exec. Use when writing or modifying C or C++ code that calls malloc/calloc/realloc/free, mmap/munmap, pthread_mutex_*, fopen/open, or any kernel/library memory or resource primitive. Use when writing Rust code inside an unsafe block that calls a raw allocation or pointer API.
---

# Memory API Misuse (CWE-690, CWE-415, CWE-401)

## What this checks

C and C++ memory and resource APIs can be called incorrectly in ways
that don't show up as a syntactic bug but produce real exploitation
primitives: a NULL-return that's dereferenced, a double-free on a
goto-out path, a lock used before init, a file descriptor that
survives `exec()` into a child process. The pattern is "API called
the wrong way, locally to a call site." Existing static analyzers
catch the easy cases; this skill is for the ones that read clean
on first pass but fail in error / edge / cleanup paths.

This skill does **not** do whole-program lifetime analysis — that's
TSAN, ASAN, Valgrind, and Rust's borrow checker. It does *local*
pattern matching at the call site.

## Vulnerable patterns

- `void *p = malloc(n); memcpy(p, src, n);` — unchecked return; if
  `malloc` returns NULL the memcpy is a NULL deref.
- `p = realloc(p, n2);` — overwriting the original pointer in place;
  if realloc fails it returns NULL and the original allocation
  leaks.
- `if (err) { free(buf); goto out; } ... out: free(buf);` — `free`
  on both an error and the cleanup path; double-free on the error
  branch.
- `pthread_mutex_t m; pthread_mutex_lock(&m);` — lock used without
  `pthread_mutex_init` (or `PTHREAD_MUTEX_INITIALIZER` at
  declaration).
- `FILE *f = fopen(path, "r");` without `e` mode flag, or
  `open(path, O_RDONLY)` without `O_CLOEXEC` — the fd survives
  `exec()` into any child the process spawns later.
- `unsafe { let p = libc::malloc(n) as *mut u8; *p = 0; }` — Rust
  unsafe with no NULL check on the libc return.
- `free(p); p = NULL;` missing — frees that don't poison the
  pointer make later use-after-free easier.

## Fix immediately

When this skill invokes, rewrite the call site to check the API
return value and place cleanup so it runs exactly once per
allocation.

**Secure pattern (C):**

```c
void *p = malloc(n);
if (p == NULL) {
    return -ENOMEM;
}
memcpy(p, src, n);
// ... use p ...
free(p);
p = NULL;
```

**Secure realloc:**

```c
void *tmp = realloc(p, n2);
if (tmp == NULL) {
    free(p);          // original is still valid; free it explicitly
    return -ENOMEM;
}
p = tmp;
```

**Secure fopen with cloexec:**

```c
FILE *f = fopen(path, "re");   // POSIX 2024: 'e' = O_CLOEXEC
if (f == NULL) return -errno;
```

**Why this works:** explicit NULL checks turn "the allocator failed
silently" into a controlled error path. Stashing the realloc result
in a temporary preserves the caller's original pointer for cleanup.
`O_CLOEXEC` ensures the fd doesn't leak into `exec()`'d children.

## Verification

After rewriting, confirm:

- [ ] Every `malloc`/`calloc`/`realloc`/`mmap` return is checked
      against NULL (or `MAP_FAILED` for `mmap`) before use
- [ ] No allocation is freed on more than one path through the
      function (use a single cleanup label or a single
      RAII/defer wrapper)
- [ ] Every `pthread_mutex_lock` / `pthread_rwlock_*` /
      `sem_wait` is preceded by a corresponding `_init` (or the
      static initializer macro at declaration)
- [ ] Every `fopen`/`open` for a file descriptor that should not
      survive across `exec()` uses `O_CLOEXEC` (or `e` mode for
      `fopen`)
- [ ] In Rust `unsafe`, every raw pointer obtained from a C API
      is checked for NULL before deref or `slice::from_raw_parts`

## References

- CWE-690 ([Unchecked Return Value to NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/690.html))
- CWE-415 ([Double Free](https://cwe.mitre.org/data/definitions/415.html))
- CWE-401 ([Missing Release of Memory after Effective Lifetime](https://cwe.mitre.org/data/definitions/401.html))
- CWE-403 ([Exposure of File Descriptor to Unintended Control Sphere](https://cwe.mitre.org/data/definitions/403.html))
