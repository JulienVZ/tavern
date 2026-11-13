# ADR 0005 — Protobuf for the gateway protocol

- Status: accepted
- Date: 2026-11-13

## Context

Clients and the server exchange real-time messages over a WebSocket gateway. Most payloads are opaque binary (MLS messages, KeyPackages, signatures). The protocol must evolve without breaking older clients, since self-hosted instances and desktop clients are not upgraded at the same moment. Decoders face untrusted input on both sides.

## Decision

- The gateway speaks **Protocol Buffers (proto3)** in binary WebSocket frames, one message per frame. Code is generated with **`prost`** (0.14).
- `.proto` files live in `crates/protocol/proto/`, under versioned packages (`tavern.gateway.v1`, `tavern.content.v1`).
- The `.proto` files are compiled in `build.rs` with **`protox`**, a pure-Rust protobuf compiler, so that contributors do not need `protoc` installed.
- Message content inside MLS application messages is also protobuf (`tavern.content.v1`). The server never parses it.
- The REST API (authentication, account, devices, KeyPackages, blobs, administration) uses JSON documented with OpenAPI (`utoipa`), with binary fields encoded as base64url. Request/response calls that are rare and benefit from standard tooling stay in REST; everything real-time goes through the gateway.
- Versioning rules are specified in [`docs/protocol.md`](../protocol.md): additive changes within a major version, field numbers never reused, a new package and endpoint for breaking changes.
- The decoders are fuzzed with `cargo-fuzz`, and round-trip properties are tested with `proptest`.

## Alternatives considered

- **JSON over WebSocket**: easy to inspect, but binary payloads must be base64-encoded (33% overhead) and schema evolution is by convention only.
- **MessagePack or CBOR**: compact, but no schema language or compatibility rules built in.
- **FlatBuffers or Cap'n Proto**: zero-copy decoding is not needed at this scale; tooling in Rust is thinner.
- **TLS presentation language everywhere** (as MLS does internally): good for crypto structures, awkward for an application protocol.
- **gRPC**: brings HTTP/2 streaming and a larger dependency tree for little gain over a single WebSocket.
- **`protoc` at build time**: the reference compiler, but an extra system dependency on three operating systems and in CI.

## Consequences

- One schema is the source of truth for both sides, living in the `protocol` crate, which depends on nothing internal.
- Two serialisations coexist (JSON for REST, protobuf for the gateway). The boundary is fixed by the rule above.
- `protox` is a new build dependency (MIT/Apache-2.0). If it lags behind a protobuf feature we need, generated code can be checked in instead.
- Binary frames are not human-readable; a debug dump tool in the `protocol` crate is worth adding when the gateway lands.
