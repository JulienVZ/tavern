# ADR 0007 — AGPL-3.0-or-later

- Status: accepted
- Date: 2026-11-13

## Context

Tavern is published so that anyone can run an instance for their friends. Users of an instance rely on the server behaving as documented: relaying ciphertext, not logging more metadata than stated. A modified server offered over the network should not be able to keep its changes private.

## Decision

- The whole repository is licensed under **AGPL-3.0-or-later**.
- Every source file carries the header `// SPDX-License-Identifier: AGPL-3.0-or-later` (or the comment syntax of its language).
- Allowed dependency licences: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0, Zlib, Unicode licences, and GPL/AGPL-compatible licences. The list is enforced by `cargo deny` through `deny.toml`.
- The server exposes its version and a link to its source through `GET /version`, which gives modified instances a simple way to meet the network clause.

## Alternatives considered

- **MIT or Apache-2.0**: maximal reuse, but allows closed forks of the server run as a service.
- **GPL-3.0**: covers distributed binaries (the client) but not a server offered over the network.
- **MPL-2.0**: file-level copyleft, weaker for a server.
- **Source-available licences** (BSL, SSPL): not open source, and incompatible with the project's goal.

## Consequences

- Anyone running a modified instance for other people must offer them the modified source.
- Some organisations avoid AGPL code; this is acceptable for a project aimed at groups of friends.
- All current dependencies (Tauri, OpenMLS, opaque-ke, LiveKit SDK, axum, sqlx, prost, rusqlite, SQLCipher) use licences compatible with AGPL-3.0. OpenSSL, if vendored for SQLCipher, is Apache-2.0 since version 3.
- Distribution through app stores with terms that conflict with the AGPL would need attention when mobile clients are considered.
- No contributor licence agreement is planned; contributions are accepted under the project licence (inbound = outbound).
