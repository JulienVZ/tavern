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
6. `unsafe` is forbidden in `protocol`, `crypto` and `server`. Elsewhere it needs a `// SAFETY:` comment and explicit review. Today the only `unsafe` code of the project is in `crates/argon2-memory` ([ADR 0015](docs/adr/0015-argon2-working-memory.md)); changes there must keep the Miri job green.
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

Fuzz the protocol decoders (needs the nightly toolchain and `cargo install cargo-fuzz`; CI does it weekly):

```bash
cd crates/protocol/fuzz
cargo +nightly fuzz run client_frame -- -max_total_time=60
```

Run a development server stack, published on the loopback interface only:

```bash
cd deploy
./scripts/init.sh --dev    # localhost names, and enables docker-compose.dev.yml
docker compose up -d --build
curl http://localhost:8080/health
```

Run the integration and end-to-end tests against that PostgreSQL, in a database of their own. `test-db.sh` creates `tavern_test` if needed and prints its URL; the tests refuse a database whose name does not end in `_test`, so the accounts you created by hand in the development instance are never touched:

```bash
TAVERN_TEST_DATABASE_URL=$(./deploy/scripts/test-db.sh) \
  cargo test --package tavern-server --package tavern-e2e-tests -- --ignored

./deploy/scripts/test-db.sh --reset    # start again from an empty test database
```

Create the first administrator invitation, then run the desktop client and enter `http://localhost:8080` as the instance address:

```bash
cd deploy && ./scripts/create-admin.sh
cd ../apps/desktop && pnpm tauri dev
```

To try several accounts or devices on one computer, keep that first client running and start the others from other terminals, each with its own keychain profile:

```bash
cd apps/desktop
pnpm client bob        # a second client
pnpm client alice-2    # a third one, and so on
```

- `pnpm tauri dev` cannot be started twice (it also serves the interface, on a fixed port). `pnpm client <profile>` reuses that server and the application it built.
- A profile is a separate keychain entry: one account and one device per profile. Use one profile per account and per device (for two accounts with two devices each: the first client plus three profiles), and reuse the same name to come back to the same device. Signing in to another account in a profile replaces its device record.
- The window title shows the profile.
- After a change to the Rust code, `tauri dev` rebuilds and restarts the first client only: close and restart the others. Changes to the interface reach every client at once.

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
- CI must pass: formatting, clippy, tests, `cargo deny`, UI checks, and the desktop build. While the repository is private, pushes and pull requests build the desktop client on Linux only; Windows and macOS are built once a day when `main` has changed, and on demand (`gh workflow run ci.yml --ref main`). A change that touches documentation only does not run the CI. Run the three systems on demand before calling a group of tasks or a milestone done. **When the repository becomes public, re-enable the three systems on pull requests** (the triggers and the `desktop` job matrix in `.github/workflows/ci.yml`).
- Say in the pull request what you could not test (for example a platform you do not have).
