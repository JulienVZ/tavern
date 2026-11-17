# ADR 0019 — MLS for direct messages: the M2 crypto plan

- Status: accepted (2026-11-16), with the maintainer's additions (sections 3, 4, 6, 7, 11, 15, 16 and 17)
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

## Decision

### 1. Library and parameters

- `openmls` 0.9.2, `openmls_traits` 0.6.0, `openmls_rust_crypto` 0.6.0 (RustCrypto, like the rest of our crypto). Not `openmls_basic_credential` (the device key already exists, in `tavern-crypto`), nor `openmls_memory_storage` or `openmls_sqlite_storage` (see 13).
- `deny.toml` ignores RUSTSEC-2026-0173 (approved 2026-11-16), with the reason above. The entry is removed as soon as `hpke-rs` or `libcrux` no longer pulls `proc-macro-error2`; `cargo deny` reports an ignored advisory that is no longer encountered, which is the signal.
- Ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` only. A group refuses any other.
- `CLAUDE.md` §3 then reads "MLS (RFC 9420) via OpenMLS 0.9 (`openmls_rust_crypto`)", and the version is noted in ADR 0002.
- The wrapper lives in `crates/crypto/src/mls/`, so that `client-core` and `server` never call OpenMLS directly, and the server's use is limited to the public group (`PublicGroup`, KeyPackage and certificate validation, signing of `Remove`), as `CLAUDE.md` §4 requires.

### 2. Credentials (format decided by ADR 0002)

- A `BasicCredential` whose identity is the protobuf `DeviceCertificate` that already exists (user id, device id, device key, issue date, signed by the AIK). The leaf's signature key is the device key, which also signs session proofs: the two uses cannot be confused, since MLS signs `"MLS 1.0 " + label` content prefixed by a length below 64 and our signatures start with the label `tavern …`.
- **A client accepts a leaf** (in a Welcome, an Add, an Update or an external commit) only if: the certificate decodes, has version 1, and verifies under the AIK of its user; that AIK equals the AIK pinned for that user in the local store (10); the leaf's signature key equals the certified device key; the certificate's user is a participant of the conversation; no two leaves have the same device id.
- **The server accepts a leaf** under the same rules, with the AIK taken from `users.identity_key`, and the device must be active (not revoked) and belong to the user.
- **A device is the pair (user id, device id)**: duplicates and changes are judged on both, so that a participant cannot block or impersonate a device of another user by certifying the same device id.
- **An update keeps its device** (accepted 2026-11-16): a leaf changed by an update, by proposal or by the committer's path, must stay the same pair; one certified for another device is refused. The same holds for an external commit, which may only replace a leaf of the joining device itself (section 5).
- A leaf that fails these checks in a commit accepted by the server is an alarm, never ignored: see 11.

### 3. KeyPackages

- Each device keeps **20 one-time KeyPackages and 1 last-resort KeyPackage** on the server. At connection, and on `KeyPackagesLow` (sent when fewer than 10 remain), it uploads up to 20.
- Lifetime: 90 days. The last-resort KeyPackage is replaced every 30 days and whenever it has been used; the server deletes expired ones.
- **Who may claim**: a user may claim the KeyPackages of another user only if they are friends, and those of their own devices. Anyone else gets `FORBIDDEN`, and nothing is consumed. Otherwise anyone could exhaust a user's 20 one-time packages and force the use of the last-resort one.
- **How often**: at most 60 claims per hour per requesting user, and 10 per hour per (requester, target) pair; beyond, `RATE_LIMITED`. A DM creation claims each user once; external commits claim nothing.
- **Which devices**: a claim returns a package for each *active* device of the target: not revoked, and connected within `TAVERN_DEVICE_INACTIVE_DAYS` (30 days by default, never more than the retention; section 15). An inactive device would otherwise be added to new conversations only to be removed from them. The same definition applies wherever this ADR says "active devices".
- The server validates each upload (signature, ciphersuite, lifetime, credential as in 2, `last_resort` extension consistent with the slot) and serves each one-time package once, deleted in the claiming transaction. The last-resort package is served only when no one-time package is left, and is not deleted.
- The client keeps the private parts in its store. OpenMLS deletes a one-time package as soon as a Welcome for it is staged, even if the device then refuses the group: a refused Welcome cannot be tried again. **The client deletes a used last-resort package after the join**, and uploads a new one: a Welcome replayed later finds no key for it.
- A package claimed from the server is checked by the claiming device before it adds anyone: OpenMLS's checks, ciphersuite, lifetime, the certificate under the identity key the device trusts for that user, and the device the server named for it.

### 4. A DM: creation, sending, receiving, catching up

- **One DM per pair of users**: a uniqueness constraint on the server (the pair, smaller user id first, is the primary key of `dm_pairs`). `POST /v1/conversations` is idempotent for a pair: it returns the existing conversation, with its current epoch, if there is one. Two creations that cross get the same conversation.
- **Joining by Welcome** (accepted 2026-11-16): a device joins only the group it expects, the conversation, generation and participants it learned from the server, and checks Tavern's parameters (ciphersuite, the instance's key as the only external sender, required capabilities) and every member against its roster. Anything else, an old Welcome replayed after the group was recreated included, is refused.
- **A participant may have no device in the group** (decided 2026-11-17): only a device of a user outside the participants is refused. A DM can be created, joined by Welcome or by external commit, and recreated (15, 17) while the other participant has no active device (away for longer than `TAVERN_DEVICE_INACTIVE_DAYS`, or with every device revoked); the creator's own leaf is always there. Such a participant joins later by external commit (5). Until then the conversation says that the messages sent now will not be readable by them.
- **Creation**: `POST /v1/conversations` with a friend reserves the conversation id. If the conversation has no group yet (epoch 0), the device claims one KeyPackage per active device of the peer and of its own user (possibly none), creates the group (group id in 17, `external_senders` = the server's key, required capabilities: our ciphersuite and the extensions we use), adds everyone in one commit, and submits it with the Welcome and the GroupInfo (`SubmitCommit`). The server builds the public state from that GroupInfo and checks that the members are exactly the active devices of the two users, and that they are friends and neither blocks the other.
- **Two devices that create the group at the same time**: the first commit for epoch 0 wins (7). The other device gets `STALE_EPOCH`, drops its own group, and joins through the Welcome it is in; a device the winner did not add (enrolled in the meantime) joins by external commit (5).
- **Sending**: content (`tavern.content.v1`) is padded (8), encrypted for the current epoch, and sent with a `client_message_id`. The server orders it in the conversation's sequence and fans it out to every other leaf, the sender's own devices included.
- **Receiving**: strictly in sequence order. A message is processed and its plaintext written in the same transaction of the local store (13), then acknowledged.
- **Catching up**: at connection, for each conversation, `FetchMessages` after the last acknowledged sequence, 200 at a time. Commits, proposals and messages come in the order they were accepted. A gap (the server no longer has what follows the last acknowledged sequence, after 30 days) is shown in the conversation; the device then rejoins by external commit (5).

### 5. New device: external commit

- A new device fetches each conversation's latest GroupInfo (with the ratchet tree) and joins with an external commit carrying its certificate.
- The server accepts it only from an active device of a participant user, and only if the commit adds that one leaf, removing at most an earlier leaf of the same device (resync).
- **Members check the same** (accepted 2026-11-16): an external commit may carry only its `ExternalInit` and at most one `Remove`, by value, of a leaf of the same pair (user id, device id) as the joining device; any other `Remove` or any other proposal is refused, with the alarm of section 11. OpenMLS adds that `Remove` itself when the group holds a leaf with the joiner's signature key; since a certificate binds that key to one device of one user, an honest joiner can only remove its own earlier leaf.
- **Nothing by reference** (decided 2026-11-17): an external commit may not refer to a stored proposal, not even a `Remove` of the server. OpenMLS's API cannot build one, but a receiver's OpenMLS would accept it; members refuse it with the alarm of section 11. These rules are decided before any rule of a member's commit.
- The joining device checks the group like a Welcome (section 4): the expected conversation, generation and participants, Tavern's parameters, every member against its roster.
- Members check the certificate as in 2. The conversation shows "Bob added a new device" ([ADR 0006](0006-no-prior-history-v1.md) and `CLAUDE.md` §5); the new device shows that it has no earlier history.
- Since a joiner has to know the GroupInfo, every commit is submitted with the GroupInfo of its new epoch, and the server keeps only the latest one.

### 6. Removing a device

- At revocation, or when it has not connected for `TAVERN_DEVICE_INACTIVE_DAYS` (30 days by default; section 15), the server stops delivering to the device, stores and sends a `Remove` proposal signed with the external sender key in each of its groups, and refuses new application messages there (`REMOVAL_PENDING`) until the removal is committed.
- The first online member device commits pending removals at once, without user action, before sending anything.
- **Clients reject every proposal from an external sender other than `Remove`**, and every external proposal signed by a key that is not in the group's `external_senders`. They also refuse an Add or a group context change that alters `external_senders`.
- Members may themselves remove only leaves of their own user (a device they replace) or leaves the server has asked to remove; the server refuses other removals in a DM, and so do clients (accepted 2026-11-16): a client never makes such a commit, and refuses one from another member with the alarm of section 11.
- **Members never send proposals on their own** (accepted 2026-11-16): a proposal received alone is stored only if it is the server's `Remove`; any other is refused and dropped. A device's own commits carry only the proposals chosen for them (the server's removals, or this commit's own adds or removals), never whatever OpenMLS has stored, and pass the same checks as other devices' commits before they are submitted. In any commit, `Update`, `PreSharedKey`, `ReInit` and custom proposals are refused; so is a commit that refers to a proposal the device refused or never received.
- **The removal of a device is shown in the conversation**, like an addition: "Bob removed a device" (or "one of your devices was removed"), whatever the cause (revocation, erasure, inactivity).

### 7. Commit ordering and conflicts

- The server accepts **one commit per epoch**: the first valid one, in a transaction that locks the conversation row. A later commit for the same epoch is refused with `STALE_EPOCH` and the sequence of the accepted one.
- A client whose commit was refused discards it (`clear_pending_commit`), processes the accepted commit, checks whether its own change is still needed, and if so commits again in the new epoch. Pending application messages are re-encrypted and resent with the same `client_message_id`.
- **Idempotent sending rests on the pair (device, `client_message_id`)**, unique in the database. A resend of a message already accepted gets the original acknowledgement (sequence and time) and is **never stored nor delivered a second time**, even if it was re-encrypted for another epoch and its bytes differ. The idempotency record outlives the message: it is kept for **twice the retention period** (60 days by default), even after the message itself is deleted, then forgotten. In return, **a client never resends a message older than the retention period**: past that, the message is shown as not sent, and the user may send it again as a new message. A retry can thus never meet a forgotten record.
- A commit is never re-sent unchanged into another epoch.

### 8. Padding

The plaintext is padded inside the content, before MLS, to the next size bucket: multiples of 256 bytes up to 1 KiB, then 2, 4, 8, 16, 32 and 64 KiB (the maximum size of a text message). OpenMLS's `padding_size` stays at 256 for its own framing. A typical message then shows the server one of a few sizes. Attachments (M5) are separate encrypted blobs with their own padding.

Format (precision validated 2026-11-16): `length of the content (4 bytes, big-endian) || content (tavern.content.v1) || zero bytes`, the whole being exactly one bucket; the header counts in the bucket, so the largest content is 64 KiB minus 4 bytes. Decoding is strict and refuses a size that is not a bucket, an announced length beyond the data, and a padding byte that is not zero. A larger bucket than needed is accepted (decided 2026-11-16): it leaves room for deliberate extra padding later, without a change of format.

### 9. Forward secrecy and message order

- `max_past_epochs = 0`: the secrets of an epoch are deleted as soon as the next commit is merged. This holds because the server accepts application messages only for the current epoch and every device processes the sequence in order: no message of a past epoch ever needs decrypting.
- Sender ratchet: `out_of_order_tolerance = 16`, `maximum_forward_distance = 1000`. Two messages sent quickly by one device can be sequenced in the reverse order; that is the only disorder there is. The key of each message is deleted once it is decrypted (OpenMLS). Since 0.9.2, a rejected message no longer advances the ratchet (GHSA-p276).
- Each device commits an update of its own leaf every 7 days, or after 100 messages it sent in the conversation, whichever comes first.
- What is kept on the device is the plaintext history in the encrypted store (ADR 0018): forward secrecy protects the transport, and deleting a message erases it from the store (`secure_delete`).

### 10. Safety numbers and key changes

- **What they cover**: the two account identity keys (AIK). Devices are certified by the AIK, so a new device changes nothing; the AIK derives from the root secret, which a password change or a recovery keeps (ADR 0017). An AIK change for a contact therefore means a new account under the same handle, or an attack.
- **Format**: for each user, `h = SHA-512("tavern safety number v1" || 0 || AIK || user id)`, then 5,199 more times `h = SHA-512(h || AIK)` (5,200 hashes in all, precision validated 2026-11-16); the first 30 bytes, in six blocks of 5 bytes, each read as a big-endian integer modulo 100,000, give 30 digits. The safety number is the two 30-digit halves, in the order of the user ids: 60 digits, shown as 12 groups of 5. The QR code holds a version byte and the two AIKs; scanning it compares the keys themselves.
- **Pinning**: the AIK of a contact is pinned in the local store when the friendship is accepted (trust on first use) and can be marked verified after comparison.
- **On change**: never accepted silently. Every conversation with that contact shows a warning; the user must acknowledge before sending again; a verified contact loses the verified mark and gets the stronger warning. Every device of the user shows it, since each pins on its own.

### 11. A leaf that fails validation

If a client finds, in a commit the server accepted, a leaf whose certificate does not verify or whose AIK is not the pinned one, it does not merge the commit. The conversation is marked broken, with a visible alarm, and the client sends nothing more in it until the user decides. This is the client's defence against a malicious server; never a silent repair.

What the user can do, from the alarm:

- **Check the safety number** with the contact, by another channel or by QR code in person. If the contact really has a new account (a new AIK), the user accepts the new key: the contact is pinned again, and the conversation is recreated (17).
- **Warn the administrator of the instance**: a certificate that does not verify, or an AIK that changed without the contact knowing, means the server misbehaves. The alarm says so in those words.
- **Recreate the conversation** (17) from its menu, with the keys pinned now. The local history is kept; the broken group is abandoned.

### 12. Ciphertext retention on the server

- A stored message (application, commit or proposal) is deleted once every leaf it was sent to has acknowledged it, and in any case after `TAVERN_MESSAGE_RETENTION_DAYS` (default 30, maximum 30), by a background task that runs every hour. A welcome is deleted when acknowledged, or after the same delay.
- The server keeps, per conversation, the public group state and the latest GroupInfo only.

### 13. MLS state on the device

- In the encrypted local store, through our own implementation of OpenMLS's `StorageProvider` (about seventy methods, all keyed reads and writes): one table `mls_state (kind, key, value)`, values encoded as OpenMLS serialises them. `openmls_sqlite_storage` cannot be used (it requires rusqlite 0.37, plain SQLite).
- The provider works on the SQLite transaction of the operation: processing a message and writing its plaintext, or merging a commit and recording its sequence, commit or fail together. A crash never leaves the group state and the history apart.
- OpenMLS changes its storage format between versions (feature `0-8-1-storage-format`). Each OpenMLS upgrade is tested on a store written by the previous version (a fixture, as in ADR 0018).

### 14. The server's public state

The server's `PublicGroup` is stored in PostgreSQL (`mls_groups`: public group state, class PUB; latest GroupInfo, class PUB), through a `PublicStorageProvider` that loads the group's entries at the start of a request and writes those changed in the same transaction as the epoch update. The OpenMLS API is synchronous; this keeps it out of async code.

### 15. Inactive devices, and restored backups

- **Inactive devices**: a device that has not connected for `TAVERN_DEVICE_INACTIVE_DAYS` (default: the retention, 30 days; never more than `TAVERN_MESSAGE_RETENTION_DAYS`, the server refuses to start otherwise) is removed from its groups by the server as in 6, without being revoked. Beyond the retention the device has to rejoin by external commit anyway, since what it missed is gone; keeping it a member longer would only keep a useless leaf, to which every message is still encrypted. When it comes back (its session may still be valid: sessions last 90 days without use), it rejoins each conversation by external commit and shows in each one: "this device was away from <date> to <date>; messages from that time are not available here".
- **A restored database backup** rewinds the server: its epochs are behind the devices', and what followed the backup is gone. In v1 the repair is simple. `restore.sh` increments an **instance generation** (a counter in the database), announced in `Ready`.
- **Every session is revoked first.** The restored database lists as active the devices revoked after the backup, a stolen one included. So the server, when it starts on a generation it has not handled yet, revokes every session of the instance before serving anything, and records for every account a security notice `INSTANCE_RESTORED` ([ADR 0016](0016-security-notices.md)) with the date of the backup. Every device must then sign in again with the password, and the TOTP code if it is enabled, before any other action; a device still known to the restored database reopens itself (ADR 0017), the others are enrolled anew. A revoked device that came back can therefore do nothing without the password.
- **The restore notice** is shown after that sign-in and acknowledged per device, like every security notice. It gives the date of the backup, says that messages sent after it may be missing, and asks the user to check their list of devices and to **revoke again the devices they had revoked since**.
- **Conversations are recreated**: from the new generation on, the server accepts, in each conversation that existed at the time of the backup, only the recreation of its group (17). A signed-in device recreates each of its conversations with the same members, unless another device has already done it; each conversation shows "the instance was restored from a backup of <date>: messages sent after that date may be missing". A DM created after the backup no longer exists on the server: the device creates it again for the same pair (4) and keeps its local history under it.
- The restored database also holds the server's part of the local store keys of that date (ADR 0017): devices enrolled after the backup start over as new devices, without their local history.
- Future evolution, not in v1: rebuild the server's public state from a GroupInfo and a ratchet tree uploaded by a member, which would keep the groups and their epochs.

### 16. Unfriending and blocking once a DM exists

- **Unfriending** (by either user): the DM and its group are kept. The server refuses new application messages from both sides (`FORBIDDEN`) and any new leaf (Add, external commit); it still accepts the removal of leaves, updates of one's own leaf, and its own `Remove` proposals, so that a revoked device still leaves the group. Both users see the conversation read-only, with its history: "You are no longer friends with @bob. Become friends again to write." Becoming friends again reopens the same DM (4); devices enrolled in the meantime join by external commit.
- **Blocking** ends the friendship, so the DM becomes read-only as above for both. The blocker sees "You blocked @bob", with an action to unblock. The blocked user sees the same text as after an unfriending: the block itself is not disclosed, consistently with the friend requests that are dropped silently (`protocol.md` §5.3). Messages accepted before the block are still delivered.
- Nothing is deleted: the conversation, its messages within the retention and the local histories stay.

### 17. Recreating a conversation's group

- The group id is the conversation id followed by a 32-bit **group generation**, 0 for the first group. Recreating gives the conversation a new MLS group, generation + 1, with the current devices of its participants: a new first commit with its Welcome, built and checked as in 4.
- It is used after a restored backup (15) and for a broken conversation (11). Any device of a participant may do it; the server accepts it when the conversation needs it (new instance generation) or when the user asks (11), at most once per hour per conversation, and refuses messages for the old group from then on.
- The local history stays under the same conversation; the conversation shows the recreation and why. Ciphertext still stored for the old group is deleted.

### 18. Tests

- **`crypto`**: unit tests and property tests (`proptest`) of the wrapper: credential checks (each failing case), KeyPackage validation, external proposals other than `Remove` refused, `external_senders` changes refused, padding buckets, safety number vectors frozen, padding and serialization round trips.
- **`client-core`**: the storage provider against OpenMLS's own scenarios (create, add, update, remove, external commit), crash between processing and writing (nothing half-written), storage fixture for upgrades.
- **Server integration (PostgreSQL)**: one commit per epoch under concurrent submissions, `STALE_EPOCH` and `REMOVAL_PENDING`; an accepted resend, even re-encrypted, returns the original acknowledgement and adds no row and no delivery, also after the message was deleted; the idempotency record is forgotten after twice the retention, and a client refuses to resend a message older than the retention; a new instance generation revokes every session once, and records the restore notice for every account; KeyPackage claim (one-time once, last resort, refused to a non-friend with nothing consumed, own devices allowed, rate limits per requester and per pair); one DM per pair, including two simultaneous `POST /v1/conversations` that get the same id; validation of new leaves; retention purge; removal of inactive devices; `TAVERN_DEVICE_INACTIVE_DAYS` above the retention refused at start-up.
- **End to end**: two users, two devices each, become friends and exchange messages; both users create the DM at the same time and end up in one group; a device offline catches up; a new device joins by external commit and the others see it; a revoked device is removed, the others see it, and it cannot read what follows; a commit conflict between two devices resolves without visible error; unfriending and blocking make the DM read-only on both sides and refriending reopens it; a key change shows the warning; a broken conversation is recreated; after a restored backup (new instance generation), every device must sign in again with the password (and TOTP) before anything else, a device revoked after the backup cannot act without it, every user sees the restore notice asking to check their devices, and every conversation is recreated.
- **"Only ciphertext in the database"**: the end-to-end test sends messages containing unique markers, then reads every `text` and `bytea` column of every table (and the server's log output) and fails if a marker appears.
- **Fuzzing** (`cargo-fuzz`): the server's decoding of `SubmitCommit`, `SendMessage` and KeyPackage uploads.

## Implementation

### Task 3: the wrapper (`crates/crypto/src/mls/`)

- Sections 1 (parameters, `Provider` = RustCrypto + the caller's storage), 2 (`credential`: `Roster`, `verify_leaf`, `verify_members`), 3 (`key_package`: building, and `validate_upload` for the server), 6 on the client side and 11 (`policy`, applied by `Group::process`), 8 (`padding`), 9 (parameters), 10 (`safety_number`, computation and format), 17 (`group_id`). `Group` wraps one conversation's OpenMLS group: create, add, join by Welcome, encrypt, process, update, commit pending proposals, remove, merge or discard a pending commit.
- OpenMLS crates are pinned to exact versions: an upgrade can change the storage format (section 13).
- `openmls_memory_storage` is in the dependency graph through `openmls_rust_crypto`; it is used by the tests only, which `crates/crypto/tests/mls_test_storage_only.rs` enforces (no production source names it, no crate depends on it outside `[dev-dependencies]`).
- Precisions found while coding:
  - The leaf capabilities list our ciphersuite, basic credentials and the last-resort KeyPackage extension: a KeyPackage may carry only extensions its leaf lists, and OpenMLS's validation refuses the last-resort flag otherwise.
  - The group's required capabilities list basic credentials only. RFC 9420 forbids listing the default extensions (external senders, ratchet tree), and the ciphersuite is fixed by the group itself, so "our ciphersuite and the extensions we use" (section 4) amounts to that.
  - An update must keep the leaf's device (`LeafError::DeviceChanged`). Accepted on 2026-11-16, for the pair (user id, device id) and for external commits (section 2).

### Corrections after the independent review of task 3

Findings of the review, all corrected (commits from `46b90a3`):

1. External commits carry only their `ExternalInit` and at most one `Remove` of the joining device's own earlier leaf (section 5). Tests: a new device, a resync, and the refusal of a `Remove` of another device of the same user and of a device of another user.
2. Proposals received alone are stored only if they are the server's `Remove`; own commits carry only chosen proposals and pass `check_commit`; `Update`, `PreSharedKey`, `ReInit` and custom proposals are refused (section 6). `ReInit` cannot be built through OpenMLS's public API; it takes the same branch as `PreSharedKey`, which is tested.
3. `Group::join` and `join_by_external_commit` take the expected group (conversation, generation, participants) and check the required capabilities; a used last-resort KeyPackage is deleted (sections 3, 4). Test: an old Welcome replayed after recreation.
4. The external commit path is tested (see 1).
5. `DeviceSigner` and `ServerSigner` sign MLS `SignContent` only.
6. `key_package::validate_claimed` checks a claimed package; only a `ClaimedKeyPackage` can be added, so `client-core` never calls OpenMLS for it.
7. Plaintext and padding buffers are erased (`Zeroizing`, `Plaintext` printed as `<redacted>`); `key_package::build` returns the public package only.
8. `Group::create` checks every device before it writes anything; a test checks that the storage stays empty.
9. `MlsError::Alarm` and `is_alarm` mark what raises the alarm of section 11: a leaf that is not a verified device, a policy violation in a commit, a commit that refers to a refused or unknown proposal. OpenMLS's refusals are typed (`Refusal`: past epoch, later epoch, already read...).
10. A member may remove only devices of its own user, or leaves the server asked to remove; `Group::remove` and receivers refuse anything else (section 6).
11. Devices are compared on the pair (user id, device id) everywhere.
12. The guard on `openmls_memory_storage` reads the dependency graph (`cargo metadata`, renames included), and CI checks that none of its symbols is linked into the server or the client (it is re-exported by `openmls_rust_crypto`, which the graph alone does not see).
13. and 14. Tests check exact errors, the groups' actual parameters, positive witnesses, the STALE_EPOCH path, `OwnPendingCommit`, and serialization round trips by property.

## Tasks that follow (M2)

| Task | Content |
|---|---|
| 3 | `crypto/src/mls/`: wrapper, parameters, credential checks, padding, safety numbers |
| 4 | Server public state (14), commit validation, `Remove` signing |
| 5–7 | KeyPackages and their claim rules (3), friends and blocks, conversations: one DM per pair (4) |
| 8–9 | Messages, sequence, acknowledgements, idempotency, retention (7, 12); commits, GroupInfo, external commits (5, 7), removal (6), inactive devices and restore (15), recreation (17), read-only DMs (16) |
| 10–11 | Client sync engine and storage provider (13); trust: pinning, safety numbers, warnings (10, 11) |
| 12 | Tauri commands and UI |
| 13–14 | Tests (18), memory measurements, documentation |

## Validation

Validated by the maintainer on 2026-11-16: OpenMLS 0.9.2 and the RUSTSEC-2026-0173 exception with its removal condition; the parameters (20 + 1 KeyPackages, `max_past_epochs = 0`, sender ratchet tolerance, 7-day updates, padding buckets); the safety number format and the behaviour on key change. Added at validation: who may claim KeyPackages and how often (3), one DM per pair (4), unfriending and blocking (16), inactive devices removed after the retention period (15), the simplified repair after a restored backup and the recreation of a group (15, 17), what the user can do with a broken conversation (11), removals shown like additions (6), idempotent sending (7). Corrected afterwards (2026-11-16): a restored backup revokes every session, so that a device revoked after the backup cannot act without the password; the idempotency record is kept for twice the retention, and clients never resend a message older than the retention.

## Consequences

- The server decodes and validates MLS handshake messages with OpenMLS: it gains a large parser exposed to every client, hence the fuzzing and the version choice.
- OpenMLS advisories become release triggers for the server and the client.
- An OpenMLS upgrade needs a storage compatibility test on the client and the server.
- The server's knowledge grows as ADR 0002 already accepted: the ratchet tree (which devices are in which conversation) and message sizes by bucket.
- `protocol.md` changes in the tasks that implement them: group id with its generation (17), `Ready` announces the instance generation (15), the claim rules (3), the idempotency of conversation creation (4). `TAVERN_MESSAGE_RETENTION_DAYS` and `TAVERN_DEVICE_INACTIVE_DAYS` arrive with tasks 8 and 9.
