# ADR 0014 — Client secret storage at milestone M1

- Status: accepted
- Date: 2026-11-14

## Context

From M1 a device must remember, between launches, who it is: its account and device identifiers, its device key and its session token. `CLAUDE.md` plans an encrypted local database (SQLCipher) whose key lives in the operating system's keychain; that database arrives with M2, together with message history. Bundling SQLCipher also raises a separate question (it needs OpenSSL on Windows and Linux, which `deny.toml` currently bans), to be settled in its own ADR at the start of M2.

## Decision

At M1 the device stores **one small record per instance directly in the OS credential store**, and nothing on disk:

| Field | Purpose |
|---|---|
| Account id, handle | Recognising the account, prefilling the login screen |
| Device id | This device |
| Device key seed | Reopening the session without enrolling the device again |
| Session token | Staying signed in; removed at logout |

- Crate: `keyring` 4.2 (MIT/Apache-2.0) with its default stores: Keychain Services on macOS, Credential Manager on Windows, Secret Service on Linux.
- Access goes through a `SecretStore` trait in `client-core`, with an in-memory implementation for tests. Headless CI has no credential store.
- The entry's service name is the application identifier; its account name is the instance URL, with an optional profile suffix (`TAVERN_PROFILE`) used to run two clients on one computer during development.
- **The account identity key is never stored**, here or anywhere on the device. It is unwrapped in memory at enrolment and erased.
- A record that cannot be read (older format, corruption) is treated as absent: the user logs in and the device is enrolled again.
- When the instance says the device was revoked, the record is deleted.

## Alternatives considered

- **SQLCipher now**: brings the OpenSSL question and a schema into a milestone that has nothing else to store.
- **A file in the application data directory**: the device key would sit on disk in clear, or under a key that would itself need the keychain.
- **Tauri's store or stronghold plugins**: the secret would be handled on the webview side of the application, against the rule that keys never leave `client-core`.

## Consequences

- No local database at M1, so no migration to write when M2 introduces one: the M2 database is created fresh, and this record either stays in the keychain or moves into it.
- The application identifier is `io.github.julienvz.tavern`, final since 2026-11-14. It names the keychain entries, and from M2 the local data directory; changing it would orphan both.
- On Linux without a running Secret Service (minimal desktops, some containers) the client cannot stay signed in between launches. It reports the keychain as unavailable instead of falling back to a file.
- On Linux, `keyring` talks to the Secret Service through `zbus` 5, three sub-crates of which (`zvariant`, `zbus_names`, `zvariant_derive`) are flagged by RustSec as unmaintained because they were merged into `zbus` 6. No vulnerability is reported. The three advisories are ignored in `deny.toml` until `keyring` moves to `secret-service` 6, which is in release candidate.
- A malicious program running as the same user can read the record on every platform; this is the "compromised device" case of the threat model.
