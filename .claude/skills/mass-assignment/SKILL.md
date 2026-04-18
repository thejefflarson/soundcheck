---
name: mass-assignment
description: Use when writing code that creates or updates database records from request
  body, form data, or JSON input. Also invoke when spreading, merging, or destructuring
  request payloads directly into ORM model create/update calls without an explicit
  field allowlist.
---

# Mass Assignment Check (API3:2023)

## What this checks

Protects against mass assignment (also called auto-binding or object injection) where
an attacker adds unexpected fields like `role=admin` or `is_verified=true` to a request
body and the ORM blindly persists them. Exploitation leads to privilege escalation,
account takeover, and data corruption.

## Vulnerable patterns

- `User.objects.create(**request.json)` — Django: all request fields written to the model
- `BeanUtils.copyProperties(dto, entity)` — Spring: copies every matching field with no filter
- `db.Create(&user)` after `json.Decode(body, &user)` — GORM: decoded JSON sets all struct fields including protected ones
- `diesel::insert_into(users).values(&new_user)` where `new_user` is deserialized from the full request body without selecting fields
- `Object.assign(dbRecord, req.body)` — Express/Node: merges all body keys into the record

## Fix immediately

Flag the vulnerable pattern and explain the risk. Then suggest a fix that establishes
these properties:

1. **No ORM create/update call receives the raw request body.** Requests land in
   a dedicated input type (DTO, Pydantic model, typed struct, sealed class) that
   contains only the fields external callers may set. Fields the input type
   doesn't mention are silently dropped by the deserializer.
2. **Privileged fields are set server-side, never from input.** `role`,
   `permissions`, `is_admin`, `is_verified`, `balance`, `owner_id`, `tenant_id`
   — these come from the authenticated session or database defaults, never from
   the payload, even after "validation".
3. **DTO-to-entity copy utilities copy only named fields** or explicitly exclude
   protected ones. A blanket `BeanUtils.copyProperties(dto, entity)` with no
   ignore list is the exact bug — the safe form names the fields.
4. **The allowlist lives next to the type, not scattered at call sites.** A
   `ALLOWED = {"name", "email"}` set filtered once per endpoint is brittle; the
   typed input pattern makes omission a compile-time (or deserialization-time)
   guarantee.

Anchor — shape, not implementation:

```
struct CreateUserInput { name: String, email: String }   # no role, no is_admin
input = deserialize(request.body, as=CreateUserInput)    # unknown fields dropped
user  = User { name: input.name, email: input.email, role: DEFAULT_ROLE }
db.insert(user)
```

## Verification

Confirm the following properties hold (language-agnostic):

- [ ] No ORM create/update call receives the raw request body, deserialized payload, or spread/merged object without an explicit field allowlist or a dedicated input type that excludes sensitive columns
- [ ] Privileged fields (role, permissions, is_admin, is_verified, balance, owner_id) are never settable from external input — they are set server-side or omitted from the input type
- [ ] If a DTO-to-entity copy utility is used, it either copies only named fields or explicitly excludes protected fields

## References

- CWE-915 ([Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html))
- [OWASP API3:2023 Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
