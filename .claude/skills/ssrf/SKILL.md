---
name: ssrf
description: Use when writing code that makes HTTP requests to URLs constructed from
  user input, fetches resources from caller-specified addresses, or proxies requests
  on behalf of users. Also invoke when implementing webhook receivers or URL preview
  features.
---

# SSRF Security Check (A10:2025 / API7:2023)

## What this checks

Protects against Server-Side Request Forgery where an attacker tricks the server into
making requests to internal services, cloud metadata endpoints, or arbitrary external
hosts. Exploitation leads to internal network scanning, credential theft from cloud
metadata APIs (169.254.169.254), and access to services behind firewalls.

## Vulnerable patterns

- `requests.get(user_url)` — fetches any URL the caller supplies, including `http://169.254.169.254/`
- `http.Get(fmt.Sprintf("http://%s/api", userHost))` — host from user input reaches outbound request
- `fetch(req.body.webhookUrl)` — webhook callback to attacker-controlled or internal address
- `new URL(input).openStream()` — Java URL fetch with no host validation, follows redirects to internal IPs
- `HttpClient.send(HttpRequest.newBuilder().uri(URI.create(userInput)).build())` — unchecked URI

## Fix immediately

Flag the vulnerable code and explain the risk. Show the secure pattern below as a
suggested fix. Then continue with the original task.

**Secure pattern:**

```python
# Python — allowlist + IP validation
from urllib.parse import urlparse
import ipaddress, socket

ALLOWED_SCHEMES = {"https"}
ALLOWED_HOSTS = {"api.trusted.com", "hooks.slack.com"}
BLOCKED_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / cloud metadata
    ipaddress.ip_network("127.0.0.0/8"),
]

def safe_fetch(url: str) -> bytes:
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"Scheme not allowed: {parsed.scheme}")
    host = parsed.hostname
    if host not in ALLOWED_HOSTS:
        # Resolve and check IP even for "allowed" hosts to block DNS rebinding
        ip = ipaddress.ip_address(socket.getaddrinfo(host, None)[0][4][0])
        if any(ip in net for net in BLOCKED_NETS):
            raise ValueError(f"Host resolves to blocked network: {ip}")
    return httpx.get(url, follow_redirects=False).content
```

```go
// Go — validate before dialing
func safeFetch(rawURL string) ([]byte, error) {
    u, err := url.Parse(rawURL)
    if err != nil || u.Scheme != "https" {
        return nil, fmt.Errorf("invalid or non-https URL")
    }
    ips, _ := net.LookupIP(u.Hostname())
    for _, ip := range ips {
        if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
            return nil, fmt.Errorf("blocked internal IP: %s", ip)
        }
    }
    client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
        return http.ErrUseLastResponse // don't follow redirects
    }}
    resp, err := client.Get(rawURL)
    if err != nil { return nil, err }
    defer resp.Body.Close()
    return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}
```

**Why this works:** The allowlist restricts which hosts the server can contact. IP
validation after DNS resolution blocks requests to internal networks even if the
hostname resolves to a private IP (DNS rebinding). Disabling redirects prevents
attackers from chaining an allowed host to an internal target via 302.

## Verification

- [ ] Every outbound HTTP request using a caller-supplied URL validates the scheme, host, and resolved IP against an allowlist or blocklist before the request is sent
- [ ] Cloud metadata addresses (169.254.169.254, fd00::, link-local ranges) are explicitly blocked
- [ ] HTTP redirects are either disabled or each redirect target is re-validated against the same allowlist
- [ ] DNS resolution results are checked for private/loopback/link-local IPs before connecting

## References

- CWE-918 ([Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html))
- [OWASP A10:2025 Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
- [OWASP API7:2023 Server Side Request Forgery](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/)
