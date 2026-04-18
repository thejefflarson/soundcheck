---
name: nosql-injection
description: Use when writing MongoDB queries, Elasticsearch queries, or other NoSQL
  database operations that include user-supplied input. Also invoke when building
  query filters from request parameters or constructing aggregation pipelines with
  dynamic values.
---

# NoSQL Injection Security Check (CWE-943)

## What this checks

Protects against NoSQL injection where user input manipulates query operators or
structure. Unlike SQL injection, NoSQL injection exploits operator injection
(`$gt`, `$ne`, `$regex`) and JavaScript execution in database engines. Exploitation
leads to authentication bypass, data exfiltration, and denial of service.

## Vulnerable patterns

- `db.users.find({user: req.body.user, pass: req.body.pass})` — `{pass: {$ne: ""}}` bypasses auth
- `collection.find({"$where": f"this.name == '{user_input}'"})` — JS injection in `$where`
- `db.collection.find(JSON.parse(req.query.filter))` — arbitrary query operator injection
- `Model.find(req.query)` — Mongoose passes raw query params as operators

## Fix immediately

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **Every value destined for a query filter is type-checked as a primitive.**
   Reject anything that isn't a string, number, or boolean before it reaches the
   query builder. The classic `{pass: {$ne: ""}}` auth bypass works because the
   deserialized JSON was allowed to be an object; type-coercing it to a string
   turns `$ne` into a literal that can't match.
2. **`$where`, `$expr`, and `$function` never receive user-supplied values.**
   These operators accept JavaScript or expression strings that the database
   engine evaluates; with user input in them, the database is an interpreter
   running attacker code.
3. **Raw request bodies and query objects are not passed directly as filters.**
   Build the query object explicitly from validated, named fields — the same
   allowlist discipline that defeats mass assignment (see the `mass-assignment`
   skill for ORM-side details).

Anchor — shape, not implementation:

```
require(isinstance(username, str))                 # reject objects / arrays
user = db.users.find_one({"username": username})   # primitive, not operator
# never: db.users.find({"$where": f"this.name == '{user_input}'"})
# never: collection.find(req.body)                 # operators smuggle in
```

## Verification

- [ ] Every value in a NoSQL query filter derived from user input is explicitly type-checked as a primitive (string, number) — not an object or array that could contain query operators
- [ ] `$where`, `$expr`, and `$function` are never used with user-supplied values
- [ ] Raw request bodies or query parameters are never passed directly as database query filters

## References

- CWE-943 ([Improper Neutralization of Special Elements in Data Query Logic](https://cwe.mitre.org/data/definitions/943.html))
