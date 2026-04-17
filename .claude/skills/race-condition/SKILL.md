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

Flag the vulnerable code and explain the risk. Show the secure pattern below as a
suggested fix. Then continue with the original task.

**Secure patterns:**

```python
# Python — atomic file operation (no check-then-act)
import os
try:
    os.remove(path)  # atomic — no TOCTOU window
except FileNotFoundError:
    pass  # already gone

# Database — use atomic operations or row-level locking
# Bad: SELECT then UPDATE
# Good: single atomic UPDATE with WHERE guard
cursor.execute(
    "UPDATE accounts SET balance = balance - %s WHERE id = %s AND balance >= %s",
    (amount, user_id, amount),
)
if cursor.rowcount == 0:
    raise InsufficientFunds()
```

```go
// Go — use sync.Mutex for in-process shared state
var mu sync.Mutex
func debit(account *Account, amount int) error {
    mu.Lock()
    defer mu.Unlock()
    if account.Balance < amount {
        return ErrInsufficient
    }
    account.Balance -= amount
    return nil
}
```

**Why this works:** Atomic operations eliminate the window between check and act.
Database-level guards (WHERE clauses, row locks, serializable transactions) enforce
atomicity even under concurrent requests.

## Verification

- [ ] No check-then-act sequence on shared state (files, database rows, in-memory counters) operates without atomicity — either a single atomic operation, a lock, or a database-level guard
- [ ] Balance/counter updates use atomic increments or compare-and-swap, not read-modify-write sequences
- [ ] File operations that depend on existence or state use atomic APIs (rename, link, O_CREAT|O_EXCL) rather than check-then-act

## References

- CWE-362 ([Concurrent Execution Using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html))
- CWE-367 ([TOCTOU Race Condition](https://cwe.mitre.org/data/definitions/367.html))
