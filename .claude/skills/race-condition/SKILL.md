---
name: race-condition
description: Use when writing check-then-act sequences on shared state, file operations
  that check existence before read/write, balance updates without locking, or any code
  where two operations on the same resource are not atomic.
---

# Race Condition Security Check (CWE-362)

## What this checks

Protects against time-of-check-to-time-of-use (TOCTOU) and other race conditions where
concurrent access to shared state creates a window for attackers to manipulate data
between a check and its corresponding action. Exploitation leads to privilege escalation,
double-spend, and data corruption.

## Vulnerable patterns

- `if os.path.exists(f): os.remove(f)` — file can be swapped between check and remove
- `if user.balance >= amount: user.balance -= amount` — double-spend without locking
- `count = db.get(key); db.set(key, count + 1)` — lost update under concurrency
- `if !exists(username) { create(username) }` — duplicate creation race

## Fix immediately

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **No check-then-act sequence on shared state runs without atomicity.** The
   check and the act collapse into a single atomic operation, or both sit
   inside a lock, transaction, or database-level guard. A `SELECT` followed by
   a separate `UPDATE` is the exact bug — merge them into a conditional
   `UPDATE ... WHERE` that returns the affected row count.
2. **Balance, counter, and quota updates use atomic increments or
   compare-and-swap** — never a read, modify, write sequence in application
   code. Under concurrency the read-modify-write loses every interleaved
   update; the database or atomic type is the correct place for the mutation.
3. **File operations that depend on existence use atomic APIs** — `rename`,
   `link`, `O_CREAT|O_EXCL`, `os.makedirs(exist_ok=False)`. `os.path.exists()`
   followed by `os.open()` is TOCTOU-exploitable; the atomic flag short-circuits
   the window.
4. **Uniqueness constraints live in the database, not in application code.**
   `if !exists() { create() }` races two ways with itself; a `UNIQUE` index
   plus an insert-and-catch-duplicate pattern is race-free by construction.

Anchor — shape, not implementation:

```
# atomic DB update with guard
rows = db.execute("UPDATE accounts SET balance = balance - ? "
                  "WHERE id = ? AND balance >= ?", [amount, id, amount])
require(rows == 1)                     # rowcount is the "check"

# atomic file create
fd = open(path, O_CREAT | O_EXCL)      # fails if it already exists
```

## Verification

- [ ] No check-then-act sequence on shared state (files, database rows, in-memory counters) operates without atomicity — either a single atomic operation, a lock, or a database-level guard
- [ ] Balance/counter updates use atomic increments or compare-and-swap, not read-modify-write sequences
- [ ] File operations that depend on existence or state use atomic APIs (rename, link, O_CREAT|O_EXCL) rather than check-then-act

## References

- CWE-362 ([Concurrent Execution Using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html))
- CWE-367 ([TOCTOU Race Condition](https://cwe.mitre.org/data/definitions/367.html))
