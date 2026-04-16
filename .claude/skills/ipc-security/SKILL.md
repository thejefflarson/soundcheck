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

After rewriting, confirm the following *properties* hold for every IPC surface present in the change (criteria only apply when the relevant pattern exists):

- [ ] For every URL scheme handler present (iOS `application(_:open:url:)`, Android `<intent-filter>` with custom scheme, Windows protocol handler): the scheme, host, and path are validated against a static allowlist before any action runs
- [ ] For every exported Android component present (`android:exported="true"` activity, service, or `BroadcastReceiver`): the component is protected by `android:permission` with `android:protectionLevel="signature"`, or the receiver explicitly verifies the caller package, and sensitive Intent extras are validated against a schema before use
- [ ] For every desktop IPC socket present (Node `net.createServer`, Python `socket`, Go `net.Listen`): the listener binds to a Unix domain socket or `127.0.0.1`/`::1` — never `0.0.0.0` or a public interface — and requires an auth token or peer-cred check before handling commands
- [ ] For every Electron/renderer IPC handler present (`ipcMain.handle`, `ipcMain.on`): the handler verifies `event.senderFrame.url` origin against an allowlist, and `contextIsolation` is enabled with `nodeIntegration` disabled
- [ ] For every named pipe or XPC service handler present (Windows named pipe, macOS `NSXPCListener`, `xpc_connection_set_event_handler`): the caller identity is verified via `connection.effectiveUserIdentifier`, code-signing requirement, or pipe ACL before privileged actions run
- [ ] No `exec`/`eval`/`Runtime.exec` is called with unvalidated IPC-supplied input on any of the above surfaces

## References

- CWE-926 ([Improper Export of Android Application Components](https://cwe.mitre.org/data/definitions/926.html))
- CWE-441 ([Unintended Proxy/Intermediary](https://cwe.mitre.org/data/definitions/441.html))
- [OWASP A01:2025 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP Mobile M4:2024](https://owasp.org/www-project-mobile-top-10/)
