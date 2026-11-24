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

The client's local store is SQLCipher ([ADR 0018](docs/adr/0018-local-store-encryption.md)). On Windows and Linux the first build compiles OpenSSL from source for it (about a minute on Linux, several on Windows); Windows needs Perl for that, for example [Strawberry Perl](https://strawberryperl.com/). The system's OpenSSL is never used, and macOS needs nothing. Do not enable SQLite in sqlx: the client's SQLCipher must be the only crate that links `sqlite3`, and the server links no SQLite (CI checks it).

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

Fuzz the protocol decoders and the server's KeyPackage checks (needs the nightly toolchain and `cargo install cargo-fuzz`; CI does it weekly). The targets are `client_frame`, `server_frame`, `device_certificate`, `key_package_upload`, `application_message` and `commit`:

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

## Updating dependencies

1. Try the change first (a branch, or a copy of the manifest) and run `cargo deny check`. Report any advisory, and any licence outside the list in `deny.toml`, before going further: `deny.toml` gets no new exception without the maintainer's agreement.
2. Update with `cargo update --package <crate>` (or the version in `Cargo.toml`), then run formatting, clippy, the tests, the PostgreSQL tests and the UI checks.
3. Check the entries of `deny.toml` that name the upgraded crate or its dependents: an ignored advisory or a licence exception may no longer be needed, or may no longer be justified.
4. Some crates come with extra steps:
   - **sqlx**: its SQLite driver, `sqlx-sqlite`, is resolved though never enabled, and must accept the `libsqlite3-sys` of the client's SQLCipher (only one crate may link `sqlite3`, [ADR 0018](docs/adr/0018-local-store-encryption.md)). If an upgrade cannot be resolved for that reason, stop and report it.
   - **rusqlite, libsqlite3-sys, sqlcipher-src, openssl-src**: check that the CI passes on the three systems (it builds them on every push and pull request). The local store committed in `crates/client-core/fixtures/` must still open everywhere. An OpenSSL advisory means a client release ([ADR 0018](docs/adr/0018-local-store-encryption.md)).
   - **openmls, openmls_traits, openmls_rust_crypto**: pinned to exact versions, upgraded together. An upgrade can change the storage format of the MLS state: it needs the compatibility test of [ADR 0019](docs/adr/0019-mls-direct-messages.md) (section 13). The `RUSTSEC-2026-0173` entry of `deny.toml` goes as soon as `cargo deny` reports it as not encountered. `openmls_memory_storage` stays in `[dev-dependencies]` (a test enforces it). The server's stored public state must still load (`a_public_state_written_by_the_first_release_still_loads`, with its frozen fixture), and `crates/crypto/src/mls/no_storage.rs` is generated again from `openmls_traits`' `StorageProvider` if that trait changed (the file then no longer compiles).
   - **opaque-ke** and its curve crates: the `crypto-bigint is not linked` check of CI must stay green ([ADR 0011](docs/adr/0011-account-identity-and-primitives.md)).
   - **zxcvbn**: the `chrono is not built for any shipped target` check of CI must stay green. Once a zxcvbn release drops chrono, that check fails on its wasm32 witness: remove the step and the `RUSTSEC-2026-0543` entry of `deny.toml`.

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
- CI must pass: formatting, clippy, tests, `cargo deny`, UI checks, Miri, the server image, and the desktop build on Linux, Windows and macOS, all run on every push and pull request. A change that touches documentation only (`docs/**` and `*.md`, except `docs/database-schema.md`, which a test reads) does not run the CI. To run it again by hand: `gh workflow run ci.yml --ref <branch>`.
- Workflows reference every action by its full commit SHA, with the version in a comment (`uses: owner/name@<sha> # vX.Y.Z`), never by a tag or a branch; Dependabot keeps both up to date.
- Say in the pull request what you could not test (for example a platform you do not have).
