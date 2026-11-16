# ADR 0019 — MLS for direct messages: the M2 crypto plan

- Status: proposed
- Date: 2026-11-16

## Context

M2 delivers friends and end-to-end encrypted 1:1 conversations between users with several devices. [ADR 0002](0002-mls-via-openmls.md) chose MLS through OpenMLS and fixed the principles: one leaf per device, a basic credential carrying the device certificate, handshake in `PublicMessage` and content in `PrivateMessage`, the server as Delivery Service and Authentication Service, the server as external sender for `Remove` only, new devices by external commit. [`docs/protocol.md` §5](../protocol.md#5-messages-for-m2-friends-and-encrypted-dms) specifies the routes and gateway messages. [ADR 0017](0017-device-identity-and-sign-out.md) and [ADR 0018](0018-local-store-encryption.md) give each device its identity and an encrypted local store.

This ADR settles what is left before code is written (tasks 3 to 11 of M2): the OpenMLS version, the parameters, the validation rules on both sides, the life of KeyPackages, the recovery paths, and the tests.

## Facts established (2026-11-16)

Checked against the published crates and a throwaway program, not from memory.

### Versions

| | 0.8 branch | 0.9 branch |
|---|---|---|
| Latest | `openmls` 0.8.3 (2026-10-22), `openmls_traits` / `openmls_rust_crypto` 0.5 | `openmls` 0.9.2 (2026-10-22), `openmls_traits` / `openmls_rust_crypto` 0.6.0 |
| Security advisories of OpenMLS itself | GHSA-94v4, GHSA-p276, GHSA-gc79 backported (0.8.2, 0.8.3). **GHSA-rrmv-c79f-cf5r** (out-of-bounds panic in decoding, remotely triggerable) and **GHSA-w62v-gv48-63rh** (quadratic duplicate detection before authentication) are fixed in 0.9.0 only | All fixed in 0.9.2 |
| `cargo deny` with our `deny.toml` | **Fails**: its graph locks `libcrux-secrets` 0.0.5 (RUSTSEC-2026-0212, constant-time select on aarch64) and `libcrux-sha3` < 0.0.10 (RUSTSEC-2026-0207, RUSTSEC-2026-0208); plus RUSTSEC-2026-0173 below | **One finding**: RUSTSEC-2026-0173, `proc-macro-error2` unmaintained |
| MSRV | — | Rust 1.91 (ours: 1.94) |

The 0.8 branch is ruled out: the server decodes MLS messages from every client, and two decoding advisories are fixed only in 0.9.

RUSTSEC-2026-0173 is an "unmaintained" notice, not a vulnerability. `proc-macro-error2` 2.0.1 is a procedural macro, run at compile time only: `openmls` → `hpke-rs` 0.7 → `libcrux-sha3` 0.0.10 → `libcrux-intrinsics` → `core-models` → `hax-lib` → `hax-lib-macros` → `proc-macro-error2`. No upgrade exists. It is the successor of `proc-macro-error`, whose identical notice (RUSTSEC-2024-0370) `deny.toml` already ignores for Tauri's GTK stack.

Licences: all within our list. Sources: crates.io only.

### Smoke test of OpenMLS 0.9.2 with `openmls_rust_crypto` 0.6.0 (macOS arm64)

A throwaway program checked, in this order, everything the design below relies on:

1. `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` is supported by the RustCrypto provider (also listed in `openmls_rust_crypto/src/provider.rs`).
2. A group with the server in `external_senders`, `padding_size(256)`, `max_past_epochs`, a sender ratchet configuration, and the pure-plaintext handshake policy.
3. A last-resort KeyPackage; an Add commit is a `PublicMessage`; the new member joins by Welcome with the ratchet tree extension.
4. The server builds the group's public state (`PublicGroup::from_external`) from a GroupInfo and the ratchet tree.
5. Application messages are `PrivateMessage`s; 2 bytes and 150 bytes of content both give 318 bytes on the wire.
6. A member's update commit is validated by the server's `PublicGroup`, merged there, and merged by the other member; epochs stay equal.
7. The server issues an external `Remove`; a member receives it as a proposal from an external sender, commits it; the server validates that commit; the removed member sees itself removed; a commit for a past epoch is then refused by the server's public state. Every member, and the server, must receive the proposal before the commit that references it (`MissingProposal` otherwise): the shared sequence of `protocol.md` §5.2 already guarantees it.
8. The exporter gives 32 bytes (for M6).

Not exercised yet, left to task 3's tests: external commits, our own storage provider, credential validation.

## Decision (proposed)

### 1. Library and parameters

- `openmls` 0.9.2, `openmls_traits` 0.6.0, `openmls_rust_crypto` 0.6.0 (RustCrypto, like the rest of our crypto). Not `openmls_basic_credential` (the device key already exists, in `tavern-crypto`), nor `openmls_memory_storage` or `openmls_sqlite_storage` (see 13).
- **Requires your approval**: ignoring RUSTSEC-2026-0173 in `deny.toml`, with the reason above, to be removed when `hpke-rs` or `libcrux` drops the dependency.
- Ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` only. A group refuses any other.
- `CLAUDE.md` §3 then reads "MLS (RFC 9420) via OpenMLS 0.9 (`openmls_rust_crypto`)", and the version is noted in ADR 0002.
- The wrapper lives in `crates/crypto/src/mls/`, so that `client-core` and `server` never call OpenMLS directly, and the server's use is limited to the public group (`PublicGroup`, KeyPackage and certificate validation, signing of `Remove`), as `CLAUDE.md` §4 requires.

### 2. Credentials (format decided by ADR 0002)

- A `BasicCredential` whose identity is the protobuf `DeviceCertificate` that already exists (user id, device id, device key, issue date, signed by the AIK). The leaf's signature key is the device key, which also signs session proofs: the two uses cannot be confused, since MLS signs `"MLS 1.0 " + label` content prefixed by a length below 64 and our signatures start with the label `tavern …`.
- **A client accepts a leaf** (in a Welcome, an Add, an Update or an external commit) only if: the certificate decodes, has version 1, and verifies under the AIK of its user; that AIK equals the AIK pinned for that user in the local store (10); the leaf's signature key equals the certified device key; the certificate's user is a participant of the conversation; no two leaves have the same device id.
- **The server accepts a leaf** under the same rules, with the AIK taken from `users.identity_key`, and the device must be active (not revoked) and belong to the user.
- A leaf that fails these checks in a commit accepted by the server is an alarm, never ignored: see 11.

### 3. KeyPackages

- Each device keeps **20 one-time KeyPackages and 1 last-resort KeyPackage** on the server. At connection, and on `KeyPackagesLow` (sent when fewer than 10 remain), it uploads up to 20.
- Lifetime: 90 days. The last-resort KeyPackage is replaced every 30 days and whenever it has been used; the server deletes expired ones.
- The server validates each upload (signature, ciphersuite, lifetime, credential as in 2, `last_resort` extension consistent with the slot) and serves each one-time package once, deleted in the claiming transaction. The last-resort package is served only when no one-time package is left, and is not deleted.
- The client keeps the private parts in its store; OpenMLS deletes those of a one-time package when its Welcome is processed.

### 4. A DM: creation, sending, receiving, catching up

- **Creation**: `POST /v1/conversations` with a friend reserves the conversation id. The creating device claims one KeyPackage per active device of the peer and of its own user, creates the group (group id = conversation id, `external_senders` = the server's key, required capabilities: our ciphersuite and the extensions we use), adds everyone in one commit, and submits it with the Welcome and the GroupInfo (`SubmitCommit`). The server builds the public state from that GroupInfo and checks that the members are exactly the active devices of the two users, and that they are friends and neither blocks the other.
- **Sending**: content (`tavern.content.v1`) is padded (8), encrypted for the current epoch, and sent with a `client_message_id`. The server orders it in the conversation's sequence and fans it out to every other leaf, the sender's own devices included.
- **Receiving**: strictly in sequence order. A message is processed and its plaintext written in the same transaction of the local store (13), then acknowledged.
- **Catching up**: at connection, for each conversation, `FetchMessages` after the last acknowledged sequence, 200 at a time. Commits, proposals and messages come in the order they were accepted. A gap (the server no longer has what follows the last acknowledged sequence, after 30 days) is shown in the conversation; the device then rejoins by external commit (5).

### 5. New device: external commit

- A new device fetches each conversation's latest GroupInfo (with the ratchet tree) and joins with an external commit carrying its certificate.
- The server accepts it only from an active device of a participant user, and only if the commit adds that one leaf, removing at most an earlier leaf of the same device (resync).
- Members check the certificate as in 2. The conversation shows "Bob added a new device" ([ADR 0006](0006-no-prior-history-v1.md) and `CLAUDE.md` §5); the new device shows that it has no earlier history.
- Since a joiner has to know the GroupInfo, every commit is submitted with the GroupInfo of its new epoch, and the server keeps only the latest one.

### 6. Removing a device

- At revocation, or after 90 days without connection (15), the server stops delivering to the device, stores and sends a `Remove` proposal signed with the external sender key in each of its groups, and refuses new application messages there (`REMOVAL_PENDING`) until the removal is committed.
- The first online member device commits pending removals at once, without user action, before sending anything.
- **Clients reject every proposal from an external sender other than `Remove`**, and every external proposal signed by a key that is not in the group's `external_senders`. They also refuse an Add or a group context change that alters `external_senders`.
- Members may themselves remove only leaves of their own user (a device they replace) or leaves the server has asked to remove; the server refuses other removals in a DM.

### 7. Commit ordering and conflicts

- The server accepts **one commit per epoch**: the first valid one, in a transaction that locks the conversation row. A later commit for the same epoch is refused with `STALE_EPOCH` and the sequence of the accepted one.
- A client whose commit was refused discards it (`clear_pending_commit`), processes the accepted commit, checks whether its own change is still needed, and if so commits again in the new epoch. Pending application messages are re-encrypted and resent with the same `client_message_id`; the server returns the original acknowledgement for a retry it already accepted.
- A commit is never re-sent unchanged into another epoch.

### 8. Padding

The plaintext is padded inside the content, before MLS, to the next size bucket: multiples of 256 bytes up to 1 KiB, then 2, 4, 8, 16, 32 and 64 KiB (the maximum size of a text message). OpenMLS's `padding_size` stays at 256 for its own framing. A typical message then shows the server one of a few sizes. Attachments (M5) are separate encrypted blobs with their own padding.

### 9. Forward secrecy and message order

- `max_past_epochs = 0`: the secrets of an epoch are deleted as soon as the next commit is merged. This holds because the server accepts application messages only for the current epoch and every device processes the sequence in order: no message of a past epoch ever needs decrypting.
- Sender ratchet: `out_of_order_tolerance = 16`, `maximum_forward_distance = 1000`. Two messages sent quickly by one device can be sequenced in the reverse order; that is the only disorder there is. The key of each message is deleted once it is decrypted (OpenMLS). Since 0.9.2, a rejected message no longer advances the ratchet (GHSA-p276).
- Each device commits an update of its own leaf every 7 days, or after 100 messages it sent in the conversation, whichever comes first.
- What is kept on the device is the plaintext history in the encrypted store (ADR 0018): forward secrecy protects the transport, and deleting a message erases it from the store (`secure_delete`).

### 10. Safety numbers and key changes

- **What they cover**: the two account identity keys (AIK). Devices are certified by the AIK, so a new device changes nothing; the AIK derives from the root secret, which a password change or a recovery keeps (ADR 0017). An AIK change for a contact therefore means a new account under the same handle, or an attack.
- **Format**: for each user, `SHA-512` iterated 5,200 times over `"tavern safety number v1" || 0 || AIK || user id`; the first 30 bytes, in six blocks of 5 bytes, each taken modulo 100,000, give 30 digits. The safety number is the two 30-digit halves, in the order of the user ids: 60 digits, shown as 12 groups of 5. The QR code holds a version byte and the two AIKs; scanning it compares the keys themselves.
- **Pinning**: the AIK of a contact is pinned in the local store when the friendship is accepted (trust on first use) and can be marked verified after comparison.
- **On change**: never accepted silently. Every conversation with that contact shows a warning; the user must acknowledge before sending again; a verified contact loses the verified mark and gets the stronger warning. Every device of the user shows it, since each pins on its own.

### 11. A leaf that fails validation

If a client finds, in a commit the server accepted, a leaf whose certificate does not verify or whose AIK is not the pinned one, it does not merge the commit. The conversation is marked broken, with a visible alarm, and the client sends nothing more in it until the user decides. This is the client's defence against a malicious server; never a silent repair.

### 12. Ciphertext retention on the server

- A stored message (application, commit or proposal) is deleted once every leaf it was sent to has acknowledged it, and in any case after `TAVERN_MESSAGE_RETENTION_DAYS` (default 30, maximum 30), by a background task that runs every hour. A welcome is deleted when acknowledged, or after the same delay.
- The server keeps, per conversation, the public group state and the latest GroupInfo only.

### 13. MLS state on the device

- In the encrypted local store, through our own implementation of OpenMLS's `StorageProvider` (about seventy methods, all keyed reads and writes): one table `mls_state (kind, key, value)`, values encoded as OpenMLS serialises them. `openmls_sqlite_storage` cannot be used (it requires rusqlite 0.37, plain SQLite).
- The provider works on the SQLite transaction of the operation: processing a message and writing its plaintext, or merging a commit and recording its sequence, commit or fail together. A crash never leaves the group state and the history apart.
- OpenMLS changes its storage format between versions (feature `0-8-1-storage-format`). Each OpenMLS upgrade is tested on a store written by the previous version (a fixture, as in ADR 0018).

### 14. The server's public state

The server's `PublicGroup` is stored in PostgreSQL (`mls_groups`: public group state, class PUB; latest GroupInfo, class PUB), through a `PublicStorageProvider` that loads the group's entries at the start of a request and writes those changed in the same transaction as the epoch update. The OpenMLS API is synchronous; this keeps it out of async code.

### 15. Devices away for more than 90 days, and restored backups

- **Away for 90 days** (`TAVERN_DEVICE_INACTIVE_DAYS`, default 90): the server removes the device from its groups as in 6, without revoking it. When it comes back (its session has expired too, so the user signs in), it finds itself removed, rejoins each conversation by external commit, and shows in each one: "this device was away from <date> to <date>; messages from that time are not available here".
- **A restored database backup rewinds the public state**: the server's epochs are behind the devices', and the messages after the backup are gone. `restore.sh` increments an instance generation (a counter in the database). A device that sees a new generation at connection checks each conversation: if the server's epoch is behind its own, it uploads its current GroupInfo and ratchet tree, signed as a member; the server rebuilds its public state from the first valid upload (checking it as in 2), and the conversation shows that messages may be missing around the date of the backup. If that fails (a device that knows no newer epoch, conflicting uploads), the group is recreated with the same members, which the conversation also shows. Devices enrolled after the backup lose their local store (ADR 0017).

### 16. Tests

- **`crypto`**: unit tests and property tests (`proptest`) of the wrapper: credential checks (each failing case), KeyPackage validation, external proposals other than `Remove` refused, `external_senders` changes refused, padding buckets, safety number vectors frozen, padding and serialization round trips.
- **`client-core`**: the storage provider against OpenMLS's own scenarios (create, add, update, remove, external commit), crash between processing and writing (nothing half-written), storage fixture for upgrades.
- **Server integration (PostgreSQL)**: one commit per epoch under concurrent submissions, `STALE_EPOCH` and `REMOVAL_PENDING`, idempotent resend, KeyPackage claim (one-time once, last resort), validation of new leaves, retention purge, removal after 90 days.
- **End to end**: two users, two devices each, become friends and exchange messages; a device offline catches up; a new device joins by external commit and the others see it; a revoked device is removed and cannot read what follows; a commit conflict between two devices resolves without visible error; a key change shows the warning; a restored backup is repaired.
- **"Only ciphertext in the database"**: the end-to-end test sends messages containing unique markers, then reads every `text` and `bytea` column of every table (and the server's log output) and fails if a marker appears.
- **Fuzzing** (`cargo-fuzz`): the server's decoding of `SubmitCommit`, `SendMessage` and KeyPackage uploads.

## Tasks that follow (M2)

| Task | Content |
|---|---|
| 3 | `crypto/src/mls/`: wrapper, parameters, credential checks, padding, safety numbers |
| 4 | Server public state (14), commit validation, `Remove` signing |
| 5–7 | KeyPackages (3), friends and blocks, conversations and DM creation (4) |
| 8–9 | Messages, sequence, acknowledgements, retention (12); commits, GroupInfo, external commits (5, 7), removal (6), 90 days and restore (15) |
| 10–11 | Client sync engine and storage provider (13); trust: pinning, safety numbers, warnings (10, 11) |
| 12 | Tauri commands and UI |
| 13–14 | Tests (16), memory measurements, documentation |

## To be validated

1. OpenMLS 0.9.2 rather than 0.8.3, and ignoring RUSTSEC-2026-0173 in `deny.toml`.
2. The parameters: 20 + 1 KeyPackages, `max_past_epochs = 0`, the sender ratchet tolerance, the 7-day updates, the padding buckets.
3. The safety number format and the behaviour on key change (10, 11).
4. The handling of devices away for 90 days and of restored backups (15).

## Consequences

- The server decodes and validates MLS handshake messages with OpenMLS: it gains a large parser exposed to every client, hence the fuzzing and the version choice.
- OpenMLS advisories become release triggers for the server and the client.
- An OpenMLS upgrade needs a storage compatibility test on the client and the server.
- The server's knowledge grows as ADR 0002 already accepted: the ratchet tree (which devices are in which conversation) and message sizes by bucket.
