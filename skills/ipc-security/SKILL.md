---
name: ipc-security
description: Use when writing URL scheme handlers, Android intent receivers or exported
  activities, named pipe or socket listeners, XPC service handlers, or any IPC endpoint
  that processes caller-supplied input without validating the caller's identity or origin.
---

# IPC Security (A01:2025)

## What this checks

Detects IPC receivers that accept input without verifying the caller's identity. Open
IPC channels let malicious apps hijack URL schemes, trigger exported components, or
inject data through shared channels.

## Vulnerable patterns

- `application(_:open:url:options:)` with no scheme/host allowlist — any app can invoke your URL handler
- `<activity android:exported="true">` on sensitive screens without a permission check
- `net.createServer(conn => handle(conn.data))` bound to `0.0.0.0` without authentication
- Android broadcast receiver with no `android:permission` handling sensitive actions
- XPC handler that trusts all callers without checking `connection.effectiveUserIdentifier`

## Fix immediately

```swift
// iOS: allowlist valid URL scheme hosts
func application(_ app: UIApplication, open url: URL,
    options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    let allowed = ["action", "share"]
    guard let host = url.host, allowed.contains(host) else { return false }
    // handle url
    return true
}
```

```xml
<!-- Android: restrict exported components to same-signature callers -->
<permission android:name="com.example.INVOKE"
    android:protectionLevel="signature" />
<activity android:exported="true"
    android:permission="com.example.INVOKE" />
```

```javascript
// Node: bind to Unix socket, require auth token
const server = net.createServer(conn => {
    const token = conn.read(32);
    if (!crypto.timingSafeEqual(token, EXPECTED)) { conn.destroy(); return; }
    handle(conn);
});
server.listen('/var/run/myapp.sock'); // not 0.0.0.0
```

**Why this works:** Allowlisting callers and requiring authentication closes the channel
to untrusted processes before any privileged action is taken.

## Verification

- [ ] URL scheme handlers validate host/path against an allowlist before acting
- [ ] All exported Android components declare a `signature`-level permission
- [ ] IPC sockets bind to Unix socket or localhost, not `0.0.0.0`
- [ ] XPC handlers verify `effectiveUserIdentifier` or entitlements before processing

## References

- CWE-926 ([Improper Export of Android Application Components](https://cwe.mitre.org/data/definitions/926.html))
- CWE-441 ([Unintended Proxy/Intermediary](https://cwe.mitre.org/data/definitions/441.html))
- [OWASP A01:2025 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP Mobile M4:2024](https://owasp.org/www-project-mobile-top-10/)
