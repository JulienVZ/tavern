# ADR 0018 — Encryption of the local store

- Status: accepted (option 1, with conditions; see [Decision](#decision))
- Date: 2026-11-16

## Context

From M2 each device keeps a local database per account (ADR 0017): message history, MLS group state, contacts and their pinned identity keys, and from M5 a full-text search index over the history. Everything in it is sensitive, including the metadata: who wrote to whom, when, how often.

The key is the 256-bit random **store key** of [ADR 0017](0017-device-identity-and-sign-out.md). It is in the OS keychain while the account is signed in, and only wrapped while signed out. This ADR decides how the database itself is encrypted with that key.

`CLAUDE.md` planned SQLCipher. Bundling SQLCipher needs a crypto library, and `deny.toml` bans OpenSSL (open decision 9). Three options were to be compared at least, against six criteria: full-text search (M5), compilation on the three systems in CI, licences, binary size, maintenance, and migration effort.

Everything below was checked on 2026-11-16 against the current crates rather than from memory: the crates were read, `cargo deny` was run on throwaway projects using the project's `deny.toml`, and the variants were built and measured on macOS (arm64). Windows and Linux figures are marked as estimates where they were not measured.

## Facts established

### What rusqlite offers today

`rusqlite` 0.43 / `libsqlite3-sys` 0.40 (MIT, the maintained Rust binding) have three relevant features:

| Feature | Database engine | Crypto provider |
|---|---|---|
| `bundled` | SQLite 3.54.1 | none |
| `bundled-sqlcipher` | SQLCipher 4.20.0 (from the `sqlcipher-src` crate) | macOS: CommonCrypto (system). **Linux: the system's OpenSSL `libcrypto`, linked dynamically.** **Windows: fails unless `OPENSSL_DIR` points to an OpenSSL install.** |
| `bundled-sqlcipher-vendored-openssl` | same | OpenSSL 3.6.3 compiled from source (`openssl-src` 300.6.1, `openssl-sys` 0.9.118), linked statically, on every system |

- FTS5 is compiled in all three (`-DSQLITE_ENABLE_FTS5` in the bundled build).
- `sqlcipher-src` also ships the libtomcrypt provider (no OpenSSL), but `libsqlite3-sys` does not use it: it is meant for WebAssembly builds. Using it natively would need our own build script.
- There is no way to make `libsqlite3-sys` compile another amalgamation, such as SQLite3 Multiple Ciphers, without modifying its build script. A pull request adding it (rusqlite#1726) has been open and conflicting since August 2025; a maintainer answered that rusqlite "cannot bundle all the SQLite forks".

### Two observations on our policy

- `cargo deny` does **not** stop OpenSSL here. `deny.toml` bans the crates `openssl` and `native-tls`; the vendored variant brings `openssl-sys` and `openssl-src`, which pass. The non-vendored variant links the system `libcrypto` on Linux through a link directive, invisible to `cargo deny`.
- `openmls_sqlite_storage` 0.3.0 requires `rusqlite ^0.37` with `bundled` (plain SQLite). Only one `libsqlite3-sys` can be linked (`links = "sqlite3"`), so it cannot be combined with rusqlite 0.43. Whatever this ADR decides, the MLS state needs a storage provider of our own on top of our store; the MLS plan of M2 covers it.

### Measurements (macOS arm64, release, `opt-level = "s"`, LTO, stripped, a test program using FTS5)

| Variant | Binary | Build of the database layer | FTS5 | Encrypted file | Linked crypto |
|---|---|---|---|---|---|
| Plain SQLite (`bundled`) | 1.39 MB | 10 s | yes | — | none |
| SQLCipher + CommonCrypto (`bundled-sqlcipher`) | 1.44 MB (+0.05) | 10 s | yes | yes | Security.framework |
| SQLCipher + vendored OpenSSL | 4.68 MB (+3.3) | 34 s | yes | yes | OpenSSL, static |
| SQLite3 Multiple Ciphers 2.6.1 (`sqlite3mc-src`, our build) | 1.40 MB (+0.01) | 8 s | yes | yes, no plaintext on disk, a wrong key reads nothing | none (its own C code) |

Estimates, not measured: compiling OpenSSL from source takes several minutes on the Windows runner (its build needs Perl, present on GitHub's images) and about a minute on Linux, once per cache.

### The SQLCipher 4 format is shared

A database written by SQLCipher 4.20 with a raw 256-bit key was opened, searched (FTS5) and extended by SQLite3 Multiple Ciphers (`cipher = sqlcipher`, `legacy = 4`), then read back by SQLCipher, which saw both rows. **The file format can be chosen independently of the library**, and the library can be swapped later without re-encrypting any user's database.

### Licences, as `cargo deny` reports them

| Crate | Declared licence | Outside our list |
|---|---|---|
| `sqlcipher-src` (any SQLCipher variant) | MIT AND BSD-3-Clause AND blessing AND WTFPL | `blessing` (SQLite's public-domain blessing), `WTFPL` (libtomcrypt, shipped but not compiled in the native build) |
| `openssl-src`, `openssl-sys` | Apache-2.0 / MIT | none |
| `sqlite3mc-src` | MIT AND CC0-1.0 AND Unlicense AND (CC0-1.0 OR Apache-2.0) | `CC0-1.0`, `Unlicense` |

All of these are compatible with AGPL-3.0-or-later; they are absent from the list only because the list is short. Each option needs licence exceptions in `deny.toml`, which only the maintainer can grant.

No security advisory affects any of these crates today (`cargo deny check advisories`).

## Options

### 1. SQLCipher with OpenSSL, through rusqlite

- `bundled-sqlcipher` on macOS (CommonCrypto) and `bundled-sqlcipher-vendored-openssl` on Windows and Linux, selected with target-specific dependencies.
- **Full-text search**: FTS5, inside the encrypted file. Nothing extra.
- **CI**: works on the three systems with the upstream feature; OpenSSL is compiled from source on Windows and Linux (minutes, cached).
- **Licences**: exception for `sqlcipher-src` (`blessing`, `WTFPL`). OpenSSL itself is Apache-2.0.
- **Policy**: exception to "no OpenSSL", limited to the client, enforced in `deny.toml` (below).
- **Binary**: +3.3 MB on Windows and Linux, +0.05 MB on macOS, against an application of several megabytes.
- **Maintenance**: the best. rusqlite maintains the integration, Zetetic maintains SQLCipher (release 4.20.0 on 2026-10-27), and OpenSSL is reviewed like no other C library. OpenSSL advisories are tracked by RustSec, hence by `cargo deny`, and call for a client release. Only `libcrypto`'s symmetric primitives are reached; most OpenSSL vulnerabilities are in TLS and certificate parsing, which the client never calls.
- **Migration effort**: none at application level. The key is given with `PRAGMA key`; everything else is plain SQLite.

### 2. SQLite3 Multiple Ciphers, in the SQLCipher 4 format, without OpenSSL

- The SQLite3MC amalgamation (MIT; utelle/SQLite3MultipleCiphers, active, release 2.7.1 on 2026-11-15, one main maintainer), configured for the SQLCipher 4 scheme.
- **Full-text search**: FTS5, tested.
- **CI**: one C file compiled with `cc` on the three systems, nothing else. Fast.
- **Licences**: exceptions for `CC0-1.0` and `Unlicense` through `sqlite3mc-src`, or the amalgamation vendored in the repository under the same licences.
- **Policy**: no OpenSSL at all.
- **Binary**: +0.01 MB.
- **Maintenance**: ours. Since rusqlite will not bundle it, we keep a patched copy of `libsqlite3-sys` (`[patch.crates-io]`, about twenty lines in its build script) and redo it at each rusqlite upgrade, outside Dependabot. The crypto code is SQLite3MC's own: AES, HMAC-SHA512 and PBKDF2 in portable C, with AES-NI when available, less scrutinised than OpenSSL's or Apple's.
- **Migration effort**: none at application level, as option 1.

### 3. Plain SQLite with application-level encryption of sensitive fields

- XChaCha20-Poly1305 (already a dependency) on each sensitive column, plain SQLite underneath.
- **Full-text search**: the core problem. FTS5 needs the words in clear in its index, on disk. The alternatives all lose something: an index kept in memory and rebuilt at every start (every message decrypted at start-up, against the 2-second cold start and the 150 MB budget); or a custom tokenizer storing keyed hashes of words (no prefix or substring search, and word frequencies remain visible).
- **Metadata**: conversation ids, senders, times, sizes, row counts and the shape of the tables stay in clear on disk.
- **CI, licences, binary**: nothing to add.
- **Maintenance**: every query and every future table must think about which columns are encrypted. No filtering, sorting or joining on them. Binding each ciphertext to its row and column is a construction we design ourselves, close to what the project rules forbid.
- **Migration effort**: the highest, and it never ends.

Rejected: it protects less (metadata, search index) for more work, and it weakens M5's search.

## Recommendation

**Option 1, SQLCipher through rusqlite, with the SQLCipher 4 format and a raw key**, because it is the only option that adds no code of ours to maintain around the encryption, and its crypto is the most reviewed. **Option 2 remains the fallback**, and choosing 1 now does not close it: the format is shared, so moving to SQLite3MC later (an OpenSSL problem, binary size, build times) would change the library and no user's data.

If you prefer to keep the "no OpenSSL" rule intact, option 2 is sound; its real cost is the patched `libsqlite3-sys` that we would carry.

### What adopting option 1 means

**`deny.toml` changes, for your approval:**

1. Ban `openssl-sys` and `openssl-src`, which today pass unnoticed, and allow them only as dependencies of `libsqlite3-sys` (`wrappers = ["libsqlite3-sys"]`). Any other use of OpenSSL, on the server or in another crate, then fails the CI.
2. A licence exception for the crate `sqlcipher-src` only, for `blessing` and `WTFPL`.

**Use of SQLCipher:**

- Format SQLCipher 4 with its default settings (AES-256-CBC, HMAC-SHA512 per page). The key is the 32-byte store key, given as a raw key (`PRAGMA key = "x'…'"`): PBKDF2 is skipped, since the key is already random. The string holding it is erased after use. `sqlite3_key` through FFI would avoid the string but needs `unsafe`, which we avoid.
- `PRAGMA cipher_memory_security = ON`, `temp_store = MEMORY` (no temporary file in clear), `secure_delete = ON`, WAL journal (encrypted by SQLCipher), page cache limited explicitly (RAM budget).
- Opening refuses to continue on a wrong key or a damaged file, and never falls back to a plain database. `cipher_integrity_check` is run in tests.
- One database per account, in the application data directory (`io.github.julienvz.tavern`), under `<instance>/<profile>/<account>` names hashed so that the directory listing reveals neither the instance nor the account.
- Schema migrations versioned with `PRAGMA user_version`, in `client-core`, tested from an empty database and from each previous version.
- The search index (M5) is an FTS5 table inside the same encrypted database (`unicode61 remove_diacritics 2` tokenizer, for French accents).

**Tests:** encryption effective (no known marker readable in the file, including WAL and journal), refusal of a wrong key and of a plain file, key from ADR 0017 opening the same store after sign-out and back in, migrations, and the store built and tested in CI on the three systems.

## Decision

Accepted by the maintainer on 2026-11-16: **option 1**, SQLCipher through rusqlite, CommonCrypto on macOS and OpenSSL compiled from source on Windows and Linux, SQLCipher 4 format with a raw key. SQLite3 Multiple Ciphers stays the documented fallback (option 2); moving to it later changes no user's data.

Conditions, all applied:

1. **OpenSSL only inside SQLCipher, in the client.** `deny.toml` bans `openssl-sys` except as a dependency of `libsqlite3-sys`, and `openssl-src` except as a dependency of `openssl-sys` (that is how it is reached: it is the build dependency that compiles OpenSSL). CI fails if the server depends on OpenSSL or SQLite (`cargo tree`), if the server binary in the image links `libssl`/`libcrypto` or carries OpenSSL's version text, or if the Linux client links the system's `libssl`/`libcrypto` instead of carrying the version that `openssl-src` compiles (`readelf`, with `ldd` shown for information).
2. **Licences `blessing` and `WTFPL` for the crate `sqlcipher-src` only** (`[licenses] exceptions` in `deny.toml`).
3. **Frozen SQLCipher parameters**: compatibility 4, raw key, no PBKDF2 stretching of the key. A test checks the effective settings, and another opens a store committed in the repository (`crates/client-core/fixtures/local-store-v1.db`, written on macOS with CommonCrypto), which every later client must open on every system. A test on the three systems creates a store, closes it, reopens it with the right key and refuses a wrong one.
4. **No data in clear in the store's files**: a test writes markers (row contents, a blob, a table name, words in a full-text index), then searches the bytes of every file in the directory, while the data is still in the write-ahead log and again after closing; it also checks that no file starts with SQLite's plain header and that no temporary file appears. The same test fails if the key is not set.
5. **OpenSSL advisories**: any security advisory on OpenSSL requires a new client release, like an advisory on any library linked into the client. `cargo deny check advisories` watches `openssl-src` and `openssl-sys` through RustSec on every CI run, and Dependabot proposes their updates.

### A constraint found while applying it: sqlx and `links = "sqlite3"`

Cargo allows one crate per `links` value in the whole dependency graph, **optional dependencies included**. sqlx 0.9.0 (the server's PostgreSQL driver, latest release) keeps an optional dependency on its SQLite driver, `sqlx-sqlite` 0.9.0, which requires `libsqlite3-sys` `>=0.30.1, <0.38.0`. rusqlite 0.43 needs `libsqlite3-sys` 0.40: the two cannot be resolved together, although the server never enables SQLite.

The versions sqlx accepts are not an option: every `libsqlite3-sys` below 0.39 bundles a SQLite older than 3.54.0 and is affected by **RUSTSEC-2026-0459** (`cargo deny` fails); `libsqlite3-sys` 0.37 bundles SQLCipher 4.10.0 on SQLite 3.50.4, which also predates the FTS5 fixes of SQLite 3.53.2. sqlx's main branch accepts up to 0.39 (unreleased); a pull request for 0.40 is open ([transact-rs/sqlx#4525](https://github.com/transact-rs/sqlx/pull/4525)).

So `third_party/sqlx-sqlite-unused` replaces `sqlx-sqlite` through `[patch.crates-io]`: an empty crate with the same version and features, which only frees the `links` slot. It is never built, and building it fails with an explanation, so enabling SQLite in sqlx cannot happen by accident. It must follow sqlx's version at each upgrade, and is to be deleted as soon as a sqlx release accepts our `libsqlite3-sys`: CI fails when that happens (`third_party/sqlx-sqlite-unused/still-needed.sh`, which asks Cargo's resolver). Upstream: [transact-rs/sqlx#3211](https://github.com/transact-rs/sqlx/issues/3211) (unwanted crates in `Cargo.lock`), [rust-lang/cargo#10801](https://github.com/rust-lang/cargo/issues/10801) (disabled optional weak dependencies are resolved), [transact-rs/sqlx#4516](https://github.com/transact-rs/sqlx/issues/4516) and [#4525](https://github.com/transact-rs/sqlx/pull/4525). Approved by the maintainer on 2026-11-16 (option A), with no other `deny.toml` exception.

**Removed on 2026-11-18.** sqlx 0.9.1 accepts `libsqlite3-sys` 0.40: CI's check failed as intended, and the stand-in, its `[patch.crates-io]` entry and the check went with the upgrade to sqlx 0.9.1. `sqlx-sqlite` 0.9.1 is again in `Cargo.lock`, never built (the server enables PostgreSQL only, and CI checks that it links no SQLite).

### How the client uses SQLCipher

- `crates/client-core/src/local/`. Opening sets `PRAGMA cipher_memory_security = ON` (process-wide: SQLCipher wipes every block SQLite frees; key material lives in its locked private heap in any case), then `PRAGMA key = "x'<64 hex digits>'"`, then `PRAGMA cipher_compatibility = 4`, then reads the schema, which fails on a wrong key, a plain file or a damaged file.
- The key statement is built in a buffer that never reallocates and is erased after use; errors from that statement are reported without any detail, since some rusqlite errors carry the SQL text. `sqlite3_key` would avoid the string but needs `unsafe`.
- Then: defensive mode, untrusted schema, WAL journal (encrypted by SQLCipher), `synchronous = NORMAL`, `foreign_keys = ON`, `secure_delete = ON`, `temp_store = MEMORY`, a page cache of 2 MiB, a busy timeout of 5 s for a second window of the same profile.
- One database per account and profile: `<local data directory>/accounts/<name>/store.db`, where `<name>` is the first 16 bytes of `SHA-256("tavern local store directory v1" || 0 || user id || instance and profile)`, in hexadecimal. The directory is created with mode 0700 on Unix. The local data directory is the application's *local* one (`%LOCALAPPDATA%` on Windows, not the roaming profile: the store is useless on another computer).
- Schema versions with `PRAGMA user_version`, one transaction per migration; a store newer than the client is refused, never opened. Version 1 holds `store_info`, the account and device the store belongs to, checked at every opening. Each later feature adds its tables in its own migration: version 2 (task 10a of M2) the device's MLS state (`mls_state`), its KeyPackages (`key_packages`), its certificate (`device_certificate`) and the text of conversations (`messages`). `secure_delete` overwrites what is deleted, and the write-ahead log is checkpointed and truncated after what deletes secrets or text (ADR 0019, section 13).

### What happens to the store

| Event | Store |
|---|---|
| Sign-in to a known device | Opened with the key from the keychain record. |
| Sign-in that enrols a new device, or whose store key could not be unwrapped (ADR 0017) | Whatever was in the account's directory is deleted, a new store is created. |
| The file does not open with the right key (damaged, replaced by a plain file) | Moved aside to `unreadable.db` (replaced the next time), a new store is created, and the user is told that the local history starts again. Never deleted: it could be the victim of a bug that a later version fixes. |
| The file has gone although this device had created one (flag in the keychain record) | New store, and the user is told. |
| A newer schema, a disk or permission error | Error shown; nothing is touched. |
| Sign-out, or session ended by the instance | Closed: SQLite checkpoints the journal and SQLCipher erases the key from memory. |
| "Sign out and erase this device", or this device revoked | Closed and its directory deleted. A device revoked from elsewhere deletes it at its next sign-in attempt. |

## Consequences

- Open decision 9 of `CLAUDE.md` is settled by this ADR; `CLAUDE.md` §3 and §10 are updated with the exception.
- The client contains two crypto libraries: RustCrypto for everything we do, OpenSSL (or CommonCrypto) inside SQLCipher only.
- **Any security advisory on OpenSSL requires a new client release.** `cargo deny` watches `openssl-src` on every CI run.
- Compiling OpenSSL from source adds about a minute to a clean Linux build and several minutes on Windows (Perl is required, present on GitHub's runners); macOS builds compile no OpenSSL.
- `third_party/sqlx-sqlite-unused` lived until sqlx accepted a recent `libsqlite3-sys` (removed on 2026-11-18, with sqlx 0.9.1).
- The MLS state is stored by a storage provider of our own on this database, not by `openmls_sqlite_storage` (see the MLS plan).
- Moving to SQLite3 Multiple Ciphers stays possible without migrating data.
