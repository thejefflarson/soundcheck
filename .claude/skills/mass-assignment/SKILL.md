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

- `User.objects.create(**request.json)` -- Django: all request fields written to the model
- `BeanUtils.copyProperties(dto, entity)` -- Spring: copies every matching field with no filter
- `db.Create(&user)` after `json.Decode(body, &user)` -- GORM: decoded JSON sets all struct fields including protected ones
- `diesel::insert_into(users).values(&new_user)` where `new_user` is deserialized from the full request body without selecting fields
- `Object.assign(dbRecord, req.body)` -- Express/Node: merges all body keys into the record

## Fix immediately

Flag the vulnerable pattern, explain the risk, and show the secure allowlist-based
approach. Then continue with the original task.

**Secure pattern -- allowlist fields explicitly:**

```python
# Django -- pick only permitted fields
allowed = {"username", "email", "bio"}
data = {k: v for k, v in request.json.items() if k in allowed}
User.objects.create(**data)
```

```java
// Spring -- copy only named properties
BeanUtils.copyProperties(dto, entity, "id", "role", "isAdmin");
// Third arg = properties to IGNORE. Or use a dedicated DTO with only safe fields.
```

```go
// Go/GORM -- bind to a limited struct, not the full model
type CreateUserInput struct {
    Username string `json:"username"`
    Email    string `json:"email"`
}
var input CreateUserInput
json.NewDecoder(r.Body).Decode(&input)
user := User{Username: input.Username, Email: input.Email}
db.Create(&user)
```

```rust
// Rust/Diesel -- use a dedicated insert struct
#[derive(Deserialize, Insertable)]
#[diesel(table_name = users)]
struct NewUser {
    username: String,
    email: String,
    // role, is_admin deliberately omitted
}
```

**Why this works:** An explicit allowlist ensures only intended fields reach the
database. Attacker-injected fields like `role` or `is_admin` are silently dropped
because they are not in the permitted set or the dedicated input struct.

## Verification

Confirm the following properties hold (language-agnostic):

- [ ] No ORM create/update call receives the raw request body, deserialized payload, or spread/merged object without an explicit field allowlist or a dedicated input type that excludes sensitive columns
- [ ] Privileged fields (role, permissions, is_admin, is_verified, balance, owner_id) are never settable from external input -- they are set server-side or omitted from the input type
- [ ] If a DTO-to-entity copy utility is used, it either copies only named fields or explicitly excludes protected fields

## References

- CWE-915 ([Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html))
- [OWASP API3:2023 Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
