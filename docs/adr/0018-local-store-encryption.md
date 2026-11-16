# ADR 0018 — Encryption of the local store

- Status: proposed
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

## Consequences

- Open decision 9 of `CLAUDE.md` is settled by this ADR; `CLAUDE.md` §3 and §10 are updated with the exception.
- The client contains two crypto libraries: RustCrypto for everything we do, OpenSSL (or CommonCrypto) inside SQLCipher only.
- OpenSSL advisories become client release triggers.
- The MLS state is stored by a storage provider of our own on this database, not by `openmls_sqlite_storage` (see the MLS plan).
- Moving to SQLite3 Multiple Ciphers stays possible without migrating data.
