---
name: unsafe-api-consumption
description: Use when writing code that calls third-party APIs, parses responses from
  external services, or integrates with webhooks and callbacks from external systems.
  Also invoke when deserializing or acting on data received from partner or vendor APIs
  without validation.
---

# Unsafe API Consumption Check (API10:2023)

## What this checks

Protects against blindly trusting data from third-party APIs. External API responses
can be tampered with (via MITM, compromised provider, or supply-chain attack), contain
unexpected types or malicious payloads, or change without notice. Treating external
data as trusted leads to injection, deserialization attacks, and business logic bypass.

## Vulnerable patterns

- `data = requests.get(api_url).json(); db.execute(f"INSERT ... {data['name']}")` — external data into SQL
- `html := resp.Body; template.HTML(html)` — rendering third-party HTML without sanitization
- `Object.assign(user, externalApiResponse)` — merging unvalidated external fields into internal model
- `redirect(api_response["redirect_url"])` — following redirect from untrusted API response (open redirect / SSRF)
- `exec(api_response["script"])` — executing code from external API

## Fix immediately

Flag the vulnerable code and explain the risk. Show the secure pattern below as a
suggested fix. Then continue with the original task.

**Secure pattern:**

```python
# Python — validate and sanitize external API data
import httpx
from pydantic import BaseModel, ValidationError

class PartnerProduct(BaseModel):
    name: str
    price: float
    sku: str

MAX_RESPONSE_BYTES = 1_000_000  # 1 MB — enough for product payloads

def fetch_product(product_id: str) -> PartnerProduct:
    resp = httpx.get(
        f"https://api.partner.com/products/{product_id}",
        timeout=10.0,
        follow_redirects=False,  # don't chase partner-controlled redirects
    )
    resp.raise_for_status()
    if len(resp.content) > MAX_RESPONSE_BYTES:
        raise ValueError("Response exceeds size budget")
    # Validate against schema — rejects unexpected fields and types
    return PartnerProduct.model_validate(resp.json())

# Use validated data in queries via parameterized statements
product = fetch_product("abc123")
db.execute("INSERT INTO products (name, price, sku) VALUES (?, ?, ?)",
           (product.name, product.price, product.sku))
```

```go
// Go — typed struct + explicit field extraction
type PartnerProduct struct {
    Name  string  `json:"name" validate:"required,max=200"`
    Price float64 `json:"price" validate:"required,gte=0"`
    SKU   string  `json:"sku"   validate:"required,alphanum"`
}

// Dedicated client that doesn't follow redirects — partner-controlled
// 3xx responses can redirect to SSRF targets or cause header-injection.
var apiClient = &http.Client{
    Timeout: 10 * time.Second,
    CheckRedirect: func(*http.Request, []*http.Request) error {
        return http.ErrUseLastResponse
    },
}

func fetchProduct(id string) (*PartnerProduct, error) {
    resp, err := apiClient.Get("https://api.partner.com/products/" + url.PathEscape(id))
    if err != nil { return nil, err }
    defer resp.Body.Close()
    var p PartnerProduct
    // LimitReader caps the response body to prevent resource exhaustion.
    if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&p); err != nil {
        return nil, fmt.Errorf("invalid response: %w", err)
    }
    if err := validate.Struct(p); err != nil { return nil, err }
    return &p, nil
}
```

**Why this works:** Schema validation ensures external data matches expected types and
constraints before it enters the application. Parameterized queries prevent injection
even if validation is bypassed. Response size limits prevent resource exhaustion.

## Verification

- [ ] Every response from an external API is validated against a schema (typed struct, Pydantic model, JSON Schema, or equivalent) before any field is used in queries, rendering, or business logic
- [ ] External API data never reaches SQL, shell, template, or code execution sinks via string interpolation — only through parameterized interfaces
- [ ] HTTP responses from external APIs are size-limited to prevent resource exhaustion
- [ ] Redirects from external API responses are not followed blindly — redirect URLs are validated or redirects are disabled

## References

- CWE-20 ([Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html))
- CWE-502 ([Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html))
- [OWASP API10:2023 Unsafe Consumption of APIs](https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/)
