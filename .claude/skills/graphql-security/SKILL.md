---
name: graphql-security
description: Detects GraphQL schemas without depth limits, cost analysis, or introspection
  controls. Use when writing GraphQL schemas, resolvers, or server
  configuration. Also invoke when setting up Apollo Server, graphql-yoga,
  Strawberry, gqlgen, or any GraphQL framework without explicit depth
  limiting, cost analysis, or introspection controls.
---

# GraphQL Security Check (CWE-400)

## What this checks

Protects against GraphQL-specific attack vectors: unbounded query depth that causes
exponential resolver execution, introspection left enabled in production (exposing
the full schema to attackers), and batch/alias attacks that bypass rate limiting.

## Vulnerable patterns

- `ApolloServer({ schema })` — no depth limit, no cost analysis, introspection on by default
- Deeply nested query: `{ user { posts { comments { author { posts { ... } } } } } }`
- Alias batching: `{ a1: login(p:"x") a2: login(p:"y") ... a1000: login(p:"z") }`
- `introspection: true` in production — full schema exposed to attackers

## Fix immediately

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **Query depth is capped at a small fixed value** (typically 5–10) via a
   validation rule or middleware that runs before resolver execution. Unbounded
   depth lets a single query trigger exponential resolver work.
2. **Total query cost is bounded.** Either a cost-analysis plugin that assigns
   weights to fields and rejects over-budget queries, or alias/field-count limits
   — the goal is that a single request cannot do unbounded work regardless of
   depth. Alias batching (`a1: … a1000: …`) bypasses per-request rate limits
   unless this is enforced.
3. **Introspection is disabled in production.** Leaving it on exposes the full
   schema — including deprecated fields, admin types, and hints for targeted
   attacks — to anyone who can hit the endpoint. Gate it on an environment flag.
4. **Every credential-accepting mutation (login, passwordReset, mfaVerify) has
   a rate limit that survives alias batching** — apply per operation, not per
   HTTP request, so `a1: login … a1000: login` counts as 1000 attempts.

Anchor — shape, not implementation:

```
server = new GraphQLServer(
    schema,
    introspection = env != "production",
    validation = [depthLimit(5), costAnalysis(max=1000)],
    rate_limit = per_operation("login", 5/min),
)
```

## Verification

- [ ] Query depth is limited to a fixed maximum (typically 5-10) via a validation rule or middleware
- [ ] Introspection is disabled in production environments
- [ ] Batch/alias attacks are mitigated by cost analysis, alias limits, or per-operation rate limiting

## References

- CWE-400 ([Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html))
- CWE-200 ([Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html))
