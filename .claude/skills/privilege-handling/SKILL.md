---
name: privilege-handling
description: Detects unsafe privilege handling in SUID/SGID binaries, environment-variable trust in privileged code, insecure umask, temp-file races, and symlink-follow bugs in /tmp. Use when writing or modifying SUID/SGID-installed code, code that drops or elevates privileges via setuid/setgid/seteuid/seteuid_r, anything that reads PATH/LD_*/IFS environment variables, code that creates files in /tmp or other world-writable directories, or anything that opens a file whose path may contain a symlink controlled by a less-privileged user.
---

# Privilege Handling (CWE-271, CWE-426, CWE-377, CWE-61)

## What this checks

Privileged programs (SUID/SGID, root daemons, container init)
operate with a credentials gap. Classic mistakes: privileges
dropped in the wrong order, environment variables trusted from
an attacker-controlled shell, temp files where an attacker can
symlink-swap before write. Local pattern, cross-trust-boundary
consequence. LSMs provide defense in depth; this catches the
source-level mistake.

## Vulnerable patterns

- **Drop-order**: `setuid(getuid()); ...; system(cmd);` —
  setuid alone does not drop the saved set-user-ID on Linux;
  the process can `seteuid(0)` itself back. Correct: `setresuid`
  on all three IDs, in the right order, with return values
  checked.
- **PATH trust in privileged exec**: `system("foo")` or
  `execlp("foo", "foo", NULL)` inside a SUID binary — `foo`
  resolves via attacker-controlled `PATH`.
- **LD_PRELOAD / LD_LIBRARY_PATH trust**: the dynamic linker
  honors these even after `setuid` in some configurations; the
  privileged binary must clear them explicitly or be compiled
  with hardening.
- **IFS trust**: shell helpers invoked via `system()` parse
  arguments through `IFS`; attacker `IFS=/` mangles paths.
- **Insecure umask**: `umask(0)` or no umask call leaves
  created files world-writable.
- **mktemp race**: `tmpnam(NULL)` / `tempnam(NULL, ...)` then
  `fopen()` — attacker symlinks the returned name before fopen,
  privileged process writes through the link.
- **/tmp symlink-follow**: `open("/tmp/foo", O_WRONLY|O_CREAT)`
  with no `O_NOFOLLOW`; attacker pre-creates `/tmp/foo` as a
  symlink to `/etc/passwd`.
- **Argv-name spoofing**: code that switches behaviour based on
  `argv[0]` (multi-call binary) without canonicalizing — caller
  picks the name via `execve`'s second argument.

## Fix immediately

When this skill invokes, rewrite the call site to drop privileges
explicitly with return checks, sanitize the environment before
exec, set a restrictive umask, and use atomic temp-file APIs with
no-follow.

**Secure setresuid drop (Linux):**

```c
uid_t ruid = getuid();
gid_t rgid = getgid();
if (setresgid(rgid, rgid, rgid) != 0 ||
    setresuid(ruid, ruid, ruid) != 0) {
    abort();   // any failure here is fatal
}
// also verify by re-reading:
uid_t r, e, s;
getresuid(&r, &e, &s);
if (r != ruid || e != ruid || s != ruid) abort();
```

**Secure privileged exec — absolute path, scrubbed env:**

```c
char *envp[] = {
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin",
    "IFS= \t\n",
    NULL,
};
execve("/usr/sbin/sendmail", argv, envp);
```

**Secure temp file:**

```c
int fd = mkostemp(template, O_CLOEXEC);
// mkostemp creates and opens atomically; no fopen race.
```

**Secure open with no symlink follow:**

```c
int fd = open(path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
```

**Why this works:** `setresuid` sets all three IDs explicitly,
checked. Absolute path + scrubbed env removes PATH/IFS/LD_*
trust. `mkostemp` is atomic open-with-create. `O_NOFOLLOW` rejects
the open if the final path component is a symlink.

## Verification

After rewriting, confirm:

- [ ] Every privilege drop uses `setresuid` / `setresgid` (or
      equivalent `pthread_setugid_np` on BSD) and checks the
      return values
- [ ] Every `execve` from privileged code passes an absolute
      path and a known `envp[]`, never the inherited environment
- [ ] No `system()`, `popen()`, or `execlp/execvp` in privileged
      code paths
- [ ] Every temp-file creation uses `mkstemp` / `mkostemp` /
      `tmpfile` (which is atomic on glibc), never
      `tmpnam`/`tempnam`/`mktemp`
- [ ] Every `open()` in a world-writable directory passes
      `O_NOFOLLOW | O_CLOEXEC` (and `O_EXCL | O_CREAT` if the
      file should not pre-exist)
- [ ] `umask(077)` or `umask(022)` is set explicitly at process
      start, depending on the intended file-mode policy

## References

- CWE-271 ([Privilege Dropping / Lowering Errors](https://cwe.mitre.org/data/definitions/271.html))
- CWE-426 ([Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html))
- CWE-377 ([Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html))
- CWE-61 ([UNIX Symbolic Link Following](https://cwe.mitre.org/data/definitions/61.html))
