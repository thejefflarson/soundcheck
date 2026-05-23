---
name: numeric-trust-boundary
description: Detects untrusted numeric input that flows through a conversion, cast, or parser into a length, size, index, or authorization comparison without bounds-checking the post-conversion value. Use when writing or modifying code that calls atoi/strtol/parseInt/strconv.Atoi on user-supplied or network-supplied input, casts between signed and unsigned integer types, narrows an integer width before a bounds check, or uses an untrusted integer as an allocation size, array index, file offset, length argument to memcpy, or comparison gate for authorization or permission decisions.
---

# Numeric Trust Boundary (CWE-190, CWE-194, CWE-704, CWE-20)

## What this checks

Plain numeric-conversion bugs (`atoi("banana") == 0`, divide-by-zero,
float `==`) are correctness issues that `clang-tidy` and `eslint`
catch. This skill targets the security subset: an untrusted integer
(from `atoi`, `strtol`, wire-protocol length, JSON number) that
flows into a length, size, index, or permission sink without a
bounds check on the post-conversion value. Local pattern only —
conversion within a function or two of the sink.

## Vulnerable patterns

- **Sign-extension on cast to size_t / length**:
  ```c
  int len = (signed char)header[0];
  void *buf = malloc(len);          // len = -1 → malloc(SIZE_MAX)
  memcpy(buf, src, len);
  ```
  Signed `char` of `0xFF` is `-1`, promoted to `int -1`, converted
  to `size_t SIZE_MAX`.
- **atoi-returns-0 silently used as auth ID**: `int uid = atoi(req)`
  returns 0 on non-numeric input with no errno; "banana" becomes
  user 0 (often admin).
- **Width truncation in bounds check**:
  ```c
  if ((short)len < BUFFER_SIZE) memcpy(buf, src, len);
  ```
  `(short)len` for `len = 0x10000` is 0; bounds check passes; full
  `len` still memcpy'd.
- **Signed/unsigned comparison flip**:
  ```c
  int n = read_user_size();   // -1
  if (n < MAX_LEN) memcpy(buf, src, n);   // -1 < MAX_LEN true; n promoted to size_t = SIZE_MAX
  ```
- **Attacker-controlled divisor**:
  ```c
  int per_chunk = total / user_provided_chunks;  // user_provided_chunks == 0 → SIGFPE
  ```
- **Wraparound on length arithmetic**: `user_count * sizeof(struct
  foo)` overflows to small `total`; later memcpy uses the unwrapped
  full value → out-of-bounds write.
- **Array indexing with no bound on parsed value**: `idx =
  strtol(input)`; `table[idx]` with idx negative or beyond length.

## Fix immediately

When this skill invokes, rewrite to use a typed parser with
explicit failure (`strtoul` + `errno`, `int.from_bytes`, `strconv`
with error return), check that the parsed value is in the
*post-conversion* range the sink requires, and reject negative /
overflowing inputs explicitly.

**Secure C parse + bounds:**

```c
errno = 0;
char *end = NULL;
unsigned long len = strtoul(header, &end, 10);
if (end == header || *end != '\0' || errno == ERANGE) {
    return -EINVAL;
}
if (len > MAX_LEN) {
    return -E2BIG;
}
void *buf = malloc(len);
if (buf == NULL) return -ENOMEM;
memcpy(buf, src, len);
```

**Secure Python parse + bounds:**

```python
raw = request.args.get("uid", "")
try:
    user_id = int(raw)
except ValueError:
    abort(400)
if user_id <= 0:
    abort(400)
user = db.User.query.get(user_id)
```

**Secure multiplication with overflow check:**

```c
if (user_count > SIZE_MAX / sizeof(struct foo)) return -EOVERFLOW;
size_t total = user_count * sizeof(struct foo);
```

**Why this works:** explicit parser-with-errno separates parse
failure from valid zero. Bounds-checking the parsed value stops
sign-extension, width-truncation, and wraparound from producing
huge/negative/colliding values at the sink.

## Verification

After rewriting, confirm:

- [ ] Every conversion of untrusted input checks for parser
      failure explicitly (`errno == ERANGE`, `try/except ValueError`,
      `strconv.Atoi` error return, etc.) — `atoi` returning 0 is
      not treated as a valid integer
- [ ] Every value used as an allocation size, array index, or
      length argument is checked against a bound *after*
      conversion to the type the sink expects
- [ ] No bounds check uses a narrower type than the value being
      checked (`(short)len < BUFFER_SIZE` is wrong; check `len`
      directly)
- [ ] Signed/unsigned comparisons are avoided or both sides
      explicitly converted before comparison
- [ ] Length arithmetic on attacker-controlled values is guarded
      against wraparound
- [ ] Attacker-controlled divisors are checked against zero

## References

- CWE-190 ([Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html))
- CWE-194 ([Unexpected Sign Extension](https://cwe.mitre.org/data/definitions/194.html))
- CWE-704 ([Incorrect Type Conversion or Cast](https://cwe.mitre.org/data/definitions/704.html))
- CWE-20 ([Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html))
