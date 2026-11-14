# ADR 0013 — WebSocket stack of the gateway

- Status: accepted
- Date: 2026-11-14

## Context

The real-time gateway is a WebSocket carrying protobuf frames ([ADR 0005](0005-protobuf-protocol.md)). Both ends need a WebSocket implementation, and project rules require an ADR for every new network dependency.

## Decision

- **Server**: the WebSocket support of `axum` (feature `ws`, built on `tungstenite`). Frame and message sizes are capped at 1 MiB by the upgrade itself, before any decoding. The `tavern.v1` subprotocol is required.
- **Client**: `tokio-tungstenite` 0.30 (MIT) with rustls, from `client-core`. Never the webview's WebSocket: the session token must not reach the webview.
- **TLS**: one implementation for the whole client. `rustls` 0.23 with the `aws-lc-rs` provider, which is what `reqwest` already uses; the gateway installs it as the process default before connecting. Trust comes from the operating system's certificate store (`rustls-tls-native-roots`), consistent with the REST client.
- `ws://` is used only when the instance URL is `http://`, which the client accepts for loopback hosts only ([ADR 0010](0010-http-client-reqwest.md)).
- The client reconnects with exponential backoff (1 s to 60 s) and jitter. It does not reconnect after close codes 4002, 4003 and 4004: the session is over or was taken over.
- `futures-util` provides the stream and sink traits both ends need.

## Alternatives considered

- **`fastwebsockets`**: faster, but a lower-level API and no integration with axum's extractors.
- **Server-sent events plus REST**: simpler, but one-way; M2 needs acknowledgements and client-initiated frames on the same ordered channel.
- **The webview's WebSocket**: no Rust dependency, but tokens and frames would live in the webview and behave differently per operating system.
- **Bundled Mozilla roots (`webpki-roots`)**: identical behaviour on every system, but a self-hoster using a private certificate authority installed in the OS would be accepted by the REST client and refused by the gateway.

## Consequences

- The gateway shares the TLS provider and trust store of the REST client: an instance reachable by one is reachable by the other.
- `ring` is also compiled in the workspace, through `sqlx` on the server. Client binaries do not link it. Installing the provider explicitly avoids an ambiguous default in test builds that link both.
- The secure path (`wss://` with a real certificate) is not exercised by automated tests, which run against loopback. It is covered by the manual test on a deployed instance and must be re-checked when the TLS stack is upgraded.
