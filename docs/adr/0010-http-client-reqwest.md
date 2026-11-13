# ADR 0010 — reqwest with rustls as the client HTTP stack

- Status: accepted
- Date: 2026-11-13

## Context

`client-core` calls the instance's REST API (health check now; authentication, KeyPackages and blobs later). Project rules require an ADR for every new network dependency, and forbid calls to third parties and reliance on the webview's network stack.

## Decision

- Use **`reqwest`** (0.13) with the **`rustls`** feature and default features disabled. No OpenSSL and no platform TLS library; `deny.toml` bans `openssl` and `native-tls`.
- Requests are made from Rust only. The webview has no network permission beyond Tauri IPC (see the CSP in `tauri.conf.json`).
- Instance URLs must use `https`. Plain `http` is accepted for loopback hosts only, for local development.
- Redirects are not followed, so an instance cannot silently send the client elsewhere. Timeouts are set on every request.
- The user agent is `tavern-client/<version>` and carries no identifying information.

## Alternatives considered

- **`hyper` directly**: fewer dependencies, more code to write for TLS, pooling, JSON and multipart uploads.
- **`ureq`**: small and blocking; the client is asynchronous throughout.
- **`fetch` from the webview**: would put tokens in the webview and behave differently per OS.
- **Platform TLS (`native-tls`)**: uses the OS trust store by default, but brings OpenSSL on Linux and three different TLS behaviours.

## Consequences

- One TLS implementation (rustls) across the client, the server's database connection and, later, the gateway WebSocket.
- Certificate validation uses the roots selected by reqwest's rustls feature. Whether to trust the OS store or a bundled set, and how self-signed instances on a LAN are handled, is decided in M1 with the connection screen.
- `reqwest` and its tree must keep passing `cargo deny`.
