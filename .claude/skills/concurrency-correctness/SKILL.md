---
name: concurrency-correctness
description: Detects multi-threaded code where a lock is held across a blocking operation, lock acquisition order risks deadlock, lock-free atomics use the wrong memory ordering, or double-checked locking is missing the necessary barrier. Use when writing or modifying code that acquires multiple locks, uses atomic operations with explicit memory orders (std::memory_order_*, atomic.LoadAcquire, Ordering::Relaxed), implements lazy initialization with double-checked locking, or calls a blocking operation (I/O, sleep, await, blocking channel send) inside a locked region.
---

# Concurrency Correctness (CWE-833, CWE-820, CWE-667)

## What this checks

Concurrency bugs that read clean in isolation but produce
deadlocks, lost wakeups, or data races in production. TSAN catches
*triggered* races but not the structural mistake. This skill flags
local patterns: lock-around-blocking-call, lock-order in nested
acquires, atomic memory order, double-checked locking. Not a
replacement for whole-program ownership analysis (borrow checker,
lockdep, model checking) — those own that territory.

## Vulnerable patterns

- **Lock held across blocking I/O / await**:
  ```python
  with self._lock:
      response = await session.get(url)   # holds the lock for an RTT
  ```
  Any other thread blocked on `self._lock` waits for the network.
- **Lock held across `sleep()`** — same shape, intentionally
  stalls everyone.
- **Inconsistent lock order**: thread A takes `(L1, L2)`, thread
  B takes `(L2, L1)` — classic AB-BA deadlock.
- **Re-entrant lock on non-recursive mutex**: `mu.Lock(); ...; mu.Lock();`
  in the same goroutine/thread — Go and C++ `std::mutex` deadlock.
- **Atomic with `memory_order_relaxed` where acquire/release is
  needed**: a flag set with `relaxed` doesn't synchronize
  with the read; the reader can see the flag set before the
  writer's payload writes are visible.
- **Double-checked locking without acquire barrier**:
  ```cpp
  if (instance == nullptr) {
      std::lock_guard g(m);
      if (instance == nullptr) instance = new T();
  }
  ```
  The outer read of `instance` needs at least acquire ordering
  (use `std::atomic<T*>` with `load(memory_order_acquire)`),
  otherwise the reader may see a non-null `instance` whose
  fields haven't been published yet.
- **Lock-then-channel-send on unbuffered channel** (Go): goroutine
  receiving from the channel needs the lock to make progress →
  deadlock.
- **Async cancellation without holding the lock during cleanup**:
  cancel mid-critical-section leaves invariants broken.

## Fix immediately

When this skill invokes, rewrite to drop the lock before blocking,
fix lock order, use the right memory order, or replace the broken
double-check with a safer idiom.

**Don't hold a lock across await / I/O:**

```python
# Snapshot under lock, do I/O outside it.
async with self._lock:
    url = self._endpoint
response = await session.get(url)
```

**Consistent lock order — canonicalize before acquire:**

```cpp
void transfer(Account &a, Account &b, int amount) {
    Account *first  = (&a < &b) ? &a : &b;
    Account *second = (&a < &b) ? &b : &a;
    std::scoped_lock g(first->mu, second->mu);   // scoped_lock = deadlock-avoiding
    ...
}
```

**Correct double-checked locking:**

```cpp
static std::atomic<T*> instance{nullptr};
T *get() {
    T *p = instance.load(std::memory_order_acquire);
    if (p == nullptr) {
        std::lock_guard g(m);
        p = instance.load(std::memory_order_relaxed);
        if (p == nullptr) {
            p = new T();
            instance.store(p, std::memory_order_release);
        }
    }
    return p;
}
```

Or use `std::call_once` / a function-local `static` — correct
by construction.

**Why this works:** dropping the lock before blocking caps
critical-section duration. Canonical lock order eliminates AB-BA.
`release/acquire` on the published pointer ensures the reader
sees the constructor's writes.

## Verification

After rewriting, confirm:

- [ ] No `await`, `time.sleep`, `recv`, `send` on unbuffered
      channels, or other blocking calls inside a `with lock:` /
      `lock_guard` / `mutex.Lock()` scope
- [ ] When a function acquires two or more locks, the order is
      total — every code path that holds both acquires them in
      the same sequence (sorted by address, by name, or via
      `std::scoped_lock`)
- [ ] All `memory_order_relaxed` uses are paired with a comment
      explaining why relaxed is sufficient (counter increment for
      stats, not a synchronization flag)
- [ ] Double-checked locking uses `std::atomic` with
      `acquire`/`release`, or is replaced by `std::call_once` /
      function-local static / `sync.Once`
- [ ] No recursive lock attempt on a non-recursive mutex

## References

- CWE-833 ([Deadlock](https://cwe.mitre.org/data/definitions/833.html))
- CWE-820 ([Missing Synchronization](https://cwe.mitre.org/data/definitions/820.html))
- CWE-667 ([Improper Locking](https://cwe.mitre.org/data/definitions/667.html))
- CWE-362 ([Race Condition](https://cwe.mitre.org/data/definitions/362.html))
