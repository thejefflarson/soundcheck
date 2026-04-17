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

Flag the vulnerable code and explain the risk. Show the secure pattern below as a
suggested fix. Then continue with the original task.

**Secure pattern:**

```javascript
// Node.js / Mongoose — cast to string, reject operators
app.post("/login", async (req, res) => {
  const { user, pass } = req.body;
  // Ensure values are strings — blocks {$ne: ""} operator injection
  if (typeof user !== "string" || typeof pass !== "string") {
    return res.status(400).json({ error: "Invalid input" });
  }
  const account = await User.findOne({ user, pass: await hash(pass) });
  // ...
});
```

```python
# Python / PyMongo — validate types, never use $where
from pymongo import MongoClient

def find_user(username: str) -> dict | None:
    # Enforce string type — blocks operator injection
    if not isinstance(username, str):
        raise ValueError("username must be a string")
    return db.users.find_one({"username": username})
    # Never: db.users.find({"$where": f"this.name == '{username}'"})
```

**Why this works:** Type-checking user input to ensure it's a string (not an object
with `$` operators) prevents operator injection. Avoiding `$where` and `$expr` with
user input prevents JavaScript execution in the database engine.

## Verification

- [ ] Every value in a NoSQL query filter derived from user input is explicitly type-checked as a primitive (string, number) — not an object or array that could contain query operators
- [ ] `$where`, `$expr`, and `$function` are never used with user-supplied values
- [ ] Raw request bodies or query parameters are never passed directly as database query filters

## References

- CWE-943 ([Improper Neutralization of Special Elements in Data Query Logic](https://cwe.mitre.org/data/definitions/943.html))
