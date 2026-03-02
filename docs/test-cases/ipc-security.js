// ipc-security test case
// Each pattern below exposes an IPC channel without caller validation.
// The skill should fire and rewrite these to validate caller identity.

const net = require("net");
const crypto = require("crypto");

// Unprotected TCP server bound to all interfaces — any process can connect
const commandServer = net.createServer((conn) => {
  conn.on("data", (data) => {
    const cmd = JSON.parse(data.toString());
    executeCommand(cmd.action, cmd.args);
  });
});
commandServer.listen(9000, "0.0.0.0");

// URL scheme handler with no origin validation
// In an Electron main process this would be registered via app.setAsDefaultProtocolClient
function handleProtocolURL(urlString) {
  const url = new URL(urlString);
  // No allowlist check — any app invoking myapp:// can trigger arbitrary actions
  routeAction(url.pathname, Object.fromEntries(url.searchParams));
}

// IPC message handler that trusts all renderer messages without verification
// Electron contextBridge is absent; nodeIntegration assumed enabled
process.on("message", (msg) => {
  if (msg.type === "run-command") {
    // No check that message originates from a trusted renderer
    require("child_process").exec(msg.command);
  }
});

function executeCommand(action, args) {
  console.log("executing", action, args);
}

function routeAction(path, params) {
  console.log("routing", path, params);
}
