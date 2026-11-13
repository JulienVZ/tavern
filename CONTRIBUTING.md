# Contributing to Tavern

Thanks for your interest. Tavern is a self-hosted, end-to-end encrypted messaging application. This guide explains how to build it and what a contribution must respect.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). Contributions are accepted under the project licence, [AGPL-3.0-or-later](LICENSE).

Security problems are **not** reported through issues: see [SECURITY.md](SECURITY.md).

## Before you start

- For anything beyond a small fix, open an issue first so the design can be discussed.
- Changes to cryptography, the protocol, the database schema or the architecture need a written plan, and usually an ADR in [`docs/adr/`](docs/adr/), before code.
- Read [`docs/architecture.md`](docs/architecture.md) and [`docs/threat-model.md`](docs/threat-model.md).

## Rules that are not negotiable

1. **The server never sees content.** A feature that needs the server to read messages, files, reactions, custom emojis or media is redesigned on the client or declined. Never "temporarily in clear".
2. **No home-made cryptography.** Use OpenMLS, RustCrypto, `rustls`, `opaque-ke`.
3. **No telemetry and no third-party service**: no analytics, external CDN or remote fonts.
4. **Never log** secrets, tokens, keys, ciphertext or plaintext.
5. **Every network input is untrusted**: validate, bound sizes, set timeouts.
6. `unsafe` is forbidden in `protocol`, `crypto` and `server`. Elsewhere it needs a `// SAFETY:` comment and explicit review.
7. New dependencies must be maintained, licence-compatible and pass `cargo deny`. A new cryptographic or network dependency needs an ADR.

## Prerequisites

- Rust: the version pinned in `rust-toolchain.toml` is installed automatically by `rustup`.
- Node.js 22.12+ or 24+, and `pnpm` 12.
- Docker with Compose v2, for the server stack and the integration tests.
- The [Tauri 2 system dependencies](https://tauri.app/start/prerequisites/) for your OS.

`protoc` is not needed: `.proto` files are compiled with a pure-Rust compiler.

## Building and testing

```bash
# Rust
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo deny check

# UI
cd apps/desktop
pnpm install
pnpm --filter tavern-ui check
pnpm --filter tavern-ui test
```

Run a development server stack, published on the loopback interface only:

```bash
cd deploy
./scripts/init.sh
# set TAVERN_DOMAIN=localhost and LIVEKIT_DOMAIN=livekit.localhost in .env
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
curl http://localhost:8080/health
```

Run the server integration tests against that PostgreSQL (use the password from `deploy/.env`):

```bash
TAVERN_TEST_DATABASE_URL=postgres://tavern:<password>@localhost:5432/tavern \
  cargo test --package tavern-server -- --ignored
```

Run the desktop client, then enter `http://localhost:8080` as the instance address:

```bash
cd apps/desktop
pnpm tauri dev
```

## Code conventions

- Code, identifiers, comments, commit messages and documentation are in **English**.
- Rust: `thiserror` in libraries, `anyhow` in binaries only; no `unwrap()`/`expect()` outside tests; `tracing` for logs; `tokio` for async.
- TypeScript is strict, without `any`. Components must be keyboard-accessible, readable by screen readers, and work in the dark and light themes. Every user-visible string goes through the i18n catalogue, in English and French.
- Every source file starts with `SPDX-License-Identifier: AGPL-3.0-or-later`.
- No dead code. A `TODO` names a milestone or an issue: `TODO(M5): ...`.
- A feature is not finished without tests. Update the documentation in the same commit as the code.

## Commits and pull requests

- [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`, `security:`.
- Small, coherent commits. One topic per pull request.
- Never commit secrets, `.env` files or real data.
- CI must pass: formatting, clippy, tests, `cargo deny`, UI checks, and the desktop build on Linux, Windows and macOS.
- Say in the pull request what you could not test (for example a platform you do not have).
