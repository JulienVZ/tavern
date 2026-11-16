# sqlx-sqlite stand-in

An empty crate that takes the place of `sqlx-sqlite`, the SQLite driver of
sqlx, through `[patch.crates-io]` in the root `Cargo.toml`. It is never
built. Approved by the maintainer on 2026-11-16
([ADR 0018](../../docs/adr/0018-local-store-encryption.md#a-constraint-found-while-applying-it-sqlx-and-links--sqlite3)).

## Why it exists

Cargo allows one crate per `links` value in the whole dependency graph, and
it resolves optional dependencies that a feature names weakly
(`sqlx-sqlite?/migrate`, `sqlx-sqlite?/uuid`), even when nothing enables
them.

- The client's local store uses SQLCipher through `rusqlite` 0.43, hence
  `libsqlite3-sys` 0.40 (`links = "sqlite3"`), which bundles SQLCipher 4.20.0
  on SQLite 3.54.1.
- The server uses sqlx 0.9.0 with PostgreSQL only. sqlx still declares its
  SQLite driver, `sqlx-sqlite` 0.9.0, which requires `libsqlite3-sys`
  `>=0.30.1, <0.38.0`.

The two cannot be resolved together. Going back to a `rusqlite` that sqlx
accepts is not an option: every `libsqlite3-sys` below 0.39 bundles a SQLite
older than 3.54.0 and is affected by RUSTSEC-2026-0459.

Upstream:

- [transact-rs/sqlx#3211](https://github.com/transact-rs/sqlx/issues/3211):
  unwanted crates in `Cargo.lock` (known issue);
- [rust-lang/cargo#10801](https://github.com/rust-lang/cargo/issues/10801):
  disabled optional weak dependencies end up in the resolution;
- [transact-rs/sqlx#4516](https://github.com/transact-rs/sqlx/issues/4516):
  a sqlx release with a `libsqlite3-sys` bound that excludes
  RUSTSEC-2026-0459;
- [transact-rs/sqlx#4525](https://github.com/transact-rs/sqlx/pull/4525):
  allow `libsqlite3-sys` 0.40 (open on 2026-11-16).

## When to remove it

As soon as a **released** sqlx can be resolved with the `libsqlite3-sys` of
our `Cargo.lock` (or Cargo stops resolving disabled weak dependencies).
`still-needed.sh` asks Cargo's resolver exactly that, with our sqlx
features, and CI fails when the answer is yes. Then:

1. upgrade sqlx in the root `Cargo.toml`;
2. delete this directory, the `[patch.crates-io]` entry and the `exclude`
   entry of the workspace;
3. `cargo deny check`, the tests, and remove the mention from ADR 0018,
   `CLAUDE.md` §4 and `CONTRIBUTING.md`.

## Rules while it exists

- The version and the list of features match the real `sqlx-sqlite` that
  sqlx requires; all features are empty. When sqlx is upgraded, update the
  version here in the same commit.
- Building it fails with a message (`compile_error!`): enabling SQLite in
  sqlx is a mistake, not something to work around.
