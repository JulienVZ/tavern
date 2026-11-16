// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stand-in for sqlx's SQLite driver. It is never built: if this message
//! appears, something enabled SQLite in sqlx, which Tavern does not use.
//! See `third_party/sqlx-sqlite-unused/README.md`.

compile_error!(
    "sqlx's SQLite driver is replaced by an empty stand-in in Tavern: the server uses PostgreSQL \
     only. See third_party/sqlx-sqlite-unused/README.md."
);
