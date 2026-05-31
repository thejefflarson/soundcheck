---
name: memory-api-misuse
description: Detects function-local misuse of memory and resource APIs in C, C++, and Rust unsafe — allocations whose return value is not checked, frees on error paths that race the success path, locks initialized incorrectly, file descriptors leaked across exec. Use when writing or modifying C or C++ code that calls malloc/calloc/realloc/free, mmap/munmap, pthread_mutex_*, fopen/open, or any kernel/library memory or resource primitive. Use when writing Rust code inside an unsafe block that calls a raw allocation or pointer API.
---

# Memory API Misuse (CWE-690, CWE-415, CWE-401)

## What this checks

C, C++, and Rust unsafe memory and resource APIs called incorrectly at a single call
site — a NULL return dereferenced, a double-free on an error path, a lock used
before init, a file descriptor that survives `exec()`. Existing static analyzers
catch the easy cases; this skill targets the ones that read clean on first pass but
fail in error or cleanup paths. It does *local* pattern matching at the call site,
not whole-program lifetime analysis (that's the job of TSAN, ASAN, Valgrind, and the
Rust borrow checker).

## Vulnerable patterns

- Allocation API (`malloc`, `calloc`, `mmap`, equivalent) whose return is used without a NULL or `MAP_FAILED` check before the next dereference
- `realloc` whose return value overwrites the original pointer in place, leaking the original allocation if reallocation fails
- A buffer freed on an error path that also flows through a common cleanup label that frees it again, producing a double-free
- Mutex, rwlock, or semaphore used before its initializer (function call or static initializer macro) has run
- File-descriptor-producing call (`fopen`, `open`, equivalent) that opens an fd which must not survive `exec()` without the close-on-exec mode or flag set
- Rust `unsafe` block that calls a raw FFI allocation or pointer API and dereferences the result with no NULL check
- `free` (or equivalent) on a pointer with no immediate nulling, leaving the dangling pointer available for later use-after-free

## Fix immediately

Flag the vulnerable call site and rewrite it so the API return value is checked and
cleanup runs exactly once per allocation. Establish these properties:

1. **Every allocation return is checked before use.** A NULL or `MAP_FAILED` return
   turns into a controlled error path — never a silent dereference.
2. **`realloc` results land in a temporary first.** The original pointer remains
   valid on failure so the caller can free it deterministically; the original
   pointer is overwritten only after success is confirmed.
3. **Allocation cleanup has a single owner per path.** Use one cleanup label, one
   RAII wrapper, or one `defer`/`scope_exit` — never `free` the same allocation
   on both an error branch and a shared cleanup path.
4. **Synchronization primitives are initialized before first use.** A static
   initializer macro at declaration or a documented init call before the first
   lock — never used uninitialized.
5. **File descriptors that should not cross `exec()` are opened close-on-exec.**
   Use the close-on-exec mode flag at open time, not a follow-up `fcntl` race.
6. **Freed pointers are nulled at the same call site** so subsequent reads fault
   loudly instead of silently using freed memory.

Translate these principles to the specific allocator, lock, and fd API of the
audited file. Use the platform's documented safe forms — do not invent variants.

## Verification

After rewriting, confirm:

- [ ] Every allocation return is checked against NULL (or the API's documented failure sentinel) before use
- [ ] No allocation is freed on more than one path through the function — a single cleanup owner per allocation
- [ ] Every synchronization primitive is initialized before its first lock or wait call
- [ ] Every file descriptor that must not survive `exec()` is opened with the close-on-exec flag or mode at open time
- [ ] In Rust `unsafe`, every raw pointer obtained from an FFI API is checked for NULL before dereference or slice construction

## References

- CWE-690 ([Unchecked Return Value to NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/690.html))
- CWE-415 ([Double Free](https://cwe.mitre.org/data/definitions/415.html))
- CWE-401 ([Missing Release of Memory after Effective Lifetime](https://cwe.mitre.org/data/definitions/401.html))
- CWE-403 ([Exposure of File Descriptor to Unintended Control Sphere](https://cwe.mitre.org/data/definitions/403.html))
