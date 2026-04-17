---
name: graphql-security
description: Use when writing GraphQL schemas, resolvers, or server configuration. Also
  invoke when setting up Apollo Server, graphql-yoga, Strawberry, gqlgen, or any GraphQL
  framework without explicit depth limiting, cost analysis, or introspection controls.
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

Flag the vulnerable configuration and explain the risk. Show the secure pattern below
as a suggested fix. Then continue with the original task.

**Secure pattern:**

```javascript
// Node.js / Apollo Server
import depthLimit from 'graphql-depth-limit';
import costAnalysis from 'graphql-cost-analysis';

const server = new ApolloServer({
  schema,
  introspection: process.env.NODE_ENV !== "production",
  plugins: [
    { requestDidStart: () => ({ didResolveOperation: costAnalysis({ maximumCost: 1000 }) }) },
  ],
  validationRules: [depthLimit(5)],
});
```

```python
# Python / Strawberry
import strawberry
from strawberry.extensions import QueryDepthLimiter

schema = strawberry.Schema(
    query=Query,
    extensions=[QueryDepthLimiter(max_depth=5)],
)
# Disable introspection in production
if not DEBUG:
    schema = strawberry.Schema(query=Query, extensions=[...],
                                types=[], enable_introspection=False)
```

**Why this works:** Depth limiting prevents exponential nested queries. Cost analysis
caps total resolver work per request. Disabling introspection in production prevents
schema reconnaissance.

## Verification

- [ ] Query depth is limited to a fixed maximum (typically 5-10) via a validation rule or middleware
- [ ] Introspection is disabled in production environments
- [ ] Batch/alias attacks are mitigated by cost analysis, alias limits, or per-operation rate limiting

## References

- CWE-400 ([Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html))
- CWE-200 ([Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html))
