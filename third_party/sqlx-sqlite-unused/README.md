# sqlx-sqlite stand-in

An empty crate that takes the place of `sqlx-sqlite`, the SQLite driver of
sqlx, through `[patch.crates-io]` in the root `Cargo.toml`. It is never
built.

## Why

Cargo allows one crate per `links` value in the whole dependency graph,
optional dependencies included, even when they are never enabled.

- The client's local store uses SQLCipher through `rusqlite` 0.43, hence
  `libsqlite3-sys` 0.40 (`links = "sqlite3"`), which bundles SQLCipher 4.20.0
  on SQLite 3.54.1 ([ADR 0018](../../docs/adr/0018-local-store-encryption.md)).
- The server uses sqlx with PostgreSQL only. sqlx 0.9.0 still declares an
  optional dependency on `sqlx-sqlite` 0.9.0, which requires
  `libsqlite3-sys` `>=0.30.1, <0.38.0`.

The two cannot be resolved together. Every `libsqlite3-sys` that sqlx 0.9.0
accepts bundles a SQLite older than 3.54.0 and is affected by
RUSTSEC-2026-0459, so going back to an older `rusqlite` is not an option.

## Rules

- The version and the list of features match the real `sqlx-sqlite` that
  sqlx requires; all features are empty.
- Building it fails with a message (`compile_error!`): enabling SQLite in
  sqlx is a mistake, not something to work around.
- When sqlx is upgraded, update the version here in the same commit. If the
  new sqlx accepts the `libsqlite3-sys` of our `rusqlite`, delete this
  directory and the `[patch.crates-io]` entry instead.
