# Threat model

This document states what Tavern protects, against whom, and what it does not protect. It is meant to be read by instance admins and by users deciding whether to trust an instance. It reflects the v1 design; nothing here is implemented yet.

Related documents: [architecture](architecture.md), [protocol](protocol.md), [database schema](database-schema.md), [ADRs](adr/).

## 1. Summary

- Message content, attachments, custom emojis, reactions and call media are end-to-end encrypted. The server relays and stores ciphertext only.
- The server sees **metadata**: who talks to whom, when, how much, and the structure and names of servers. It also sees user profiles in v1.
- A compromised or malicious server cannot read past or future content of DMs and private groups. It can deny service, observe metadata and, for server channels, authorise a new visible member for future messages.
- Users who compare safety numbers detect a server that substitutes identity keys.

## 2. Assets

| Asset | Where it lives | Protection |
|---|---|---|
| Message content (text, edits, deletions, replies, mentions, reactions, link previews) | Sender and recipient devices | MLS application messages |
| Attachments, thumbnails, file names and types | Devices; ciphertext in blob storage | Per-file random key carried in an MLS message |
| Custom emojis, including animated ones | Devices; ciphertext in blob storage | Same as attachments |
| Call audio, video, screen share, data packets | Devices in the call | LiveKit frame encryption with keys from the MLS exporter |
| Passwords | The user's memory | OPAQUE; never sent to the server |
| Account root secret, and the account identity key (AIK) derived from it | Wrapped on the server; briefly in client memory | Wrapped under a password-derived key and under the recovery key ([ADR 0017](adr/0017-device-identity-and-sign-out.md)) |
| Key of a device's local store | In the OS keychain while signed in; only wrapped while signed out | Wrapped under a key that needs both a part derived from the root secret and a part held by the server, erased at revocation ([ADR 0017](adr/0017-device-identity-and-sign-out.md)) |
| Device signature keys, MLS group secrets | Device local store | SQLCipher database, key in the OS keychain |
| Local message history and search index | Device local store | Same |
| Session tokens | Device local store; SHA-256 hash on the server | Random 256-bit values, revocable |
| Recovery key | Wherever the user wrote it down | Shown once, never stored by the client or the server |
| Instance secrets (OPAQUE server setup, MLS external sender key, LiveKit API secret, TOTP encryption key) | Server host | File permissions; covered by backups |
| Metadata (see section 4) | Server database and logs | Access control only |

## 3. Adversaries

### 3.1 Curious instance admin

Has full read access to the database, blob storage, logs and server memory, and behaves otherwise honestly (does not modify the software).

- **Cannot** read message content, attachments, custom emojis, reactions, or call media, and cannot learn passwords.
- **Can** read everything listed as visible in section 4: the social graph, activity timing, server structure, profiles.
- **Can** try an offline dictionary attack on a user's password using the OPAQUE record and the server setup. Each guess costs one Argon2id evaluation. A weak password falls; it then gives access to that user's wrapped AIK.

### 3.2 Network attacker

Observes or modifies traffic between clients and the instance, or between the instance and LiveKit peers.

- All client–server traffic uses TLS 1.3 (Caddy with automatic certificates; `rustls` on the client). Media uses DTLS-SRTP on top of frame encryption.
- **Cannot** read content or metadata carried inside TLS, nor inject messages.
- **Can** see that a device talks to a given instance, traffic volumes and timing, and can tell a call from text activity. IP addresses of call participants are visible to the SFU, not to other participants, since media is relayed.
- **Can** block traffic.

### 3.3 Compromised server (active attacker with full control)

Includes a malicious admin running modified software and an intruder who took over the host.

- **Cannot** decrypt messages sent before or after the compromise in conversations it is not a member of. It holds no group secret.
- **Cannot** add a member or a device to a DM or private group: members accept an Add or an external join only for a device certificate signed by the AIK of an expected user, and reject any Add coming from the external sender.
- **Cannot** swap the key of a device already in a group: members refuse, with the alarm, a leaf that shows another signature key for a device of the group, in an update, an Add or a resync ([ADR 0019](adr/0019-mls-direct-messages.md), section 2). Forging such a leaf needs the AIK as well; for a device absent from the group, see 3.4.
- **Can** drop, delay, reorder or replay ciphertext. Replays and reordering are detected by MLS; dropping is denial of service.
- **Can** propose removals with the external sender key, or refuse delivery, to exclude members: denial of service, visible to users.
- **Can** substitute a user's AIK for someone who has never talked to that user, and so impersonate them in a new conversation. Clients pin AIKs on first use and warn on change; comparing safety numbers defeats the substitution.
- **Can** alter server-side roles and so authorise a ghost account in **server channels** for messages sent from then on. Every arrival is displayed in the channel and in the member list, and the ghost cannot read earlier messages. Channels marked private require an Add committed by an existing member and are not exposed to this. Final design at M4.
- **Can** serve wrong profiles, names and permissions, since those are server-side data.
- **Can** issue LiveKit tokens for any room. Without the MLS exporter secret the media stays unreadable; an intruder in a call is visible as a participant with no valid frames.
- **Can** run the offline password attack of section 3.1.
- **Can** bypass or disable TOTP, which it enforces itself. TOTP protects a stolen password from being used over the network by a third party; it is not a defence against the server. An honest administrator disabling a user's TOTP on request (for a lost phone) is the visible, logged form of the same power.
- **Can** withhold the Remove proposal after a kick and keep delivering to the kicked device, which is still in the group until someone commits its removal. A moderator's client commits the removal itself when it is online, which closes this window.

### 3.4 Stolen or seized device

- Powered off or locked, with full-disk encryption: the local database key sits in the OS keychain, protected by the OS login.
- Unlocked, or OS account compromised: the attacker reads the local history, holds a valid session and can read and send messages as that device until it is revoked.
- **Cannot** obtain the account root secret or the AIK private key from the device (they are not stored there), so cannot enrol further devices without the password. Any enrolment is notified to the account's other devices.
- With the password but not a device's key, an attacker holds the AIK and could certify a key of their own under that device's id, to take its place in conversations unseen. The honest server refuses it: a leaf must carry the very key and certificate the device enrolled with ([ADR 0019](adr/0019-mls-direct-messages.md), section 2). Clients refuse it too, with the alarm, but only for a device the group holds when the commit arrives. A device absent from the group at that moment is protected by the server alone: a device joining a conversation for the first time (one in no conversation yet, or one left out at creation), a device coming back by external commit after it was removed for inactivity, and every device of a recreated group. Task 11 of M2 narrows this: each device pins, in its local store, the key of every device it has seen, by user id and device id, from one group to another, and raises the alarm when one of them comes back with another key. A device a client has never seen stays protected by the server alone.
- **Cannot** read the local store of a signed-out account: its key is kept only wrapped, and opening it needs the password (through the root secret) and the server's part. Once the device is revoked the server's part is erased and the store cannot be opened at all. A signed-in device keeps its store key in the keychain and is not protected this way.
- Sees only encrypted files in the local data directory: every page of the store, its write-ahead log and its indexes are encrypted by SQLCipher (AES-256, HMAC-SHA512 per page, [ADR 0018](adr/0018-local-store-encryption.md)), and directory names are hashes. Visible: the number of accounts on the computer, the size of each store and when it was last written.
- Revoking the device from another device (or by an admin) invalidates its session and triggers Remove proposals in every group. After those commits the stolen device cannot decrypt new messages. Messages already on the device remain readable.
- If the instance is later restored from a backup older than the revocation, the device is listed as active again, but cannot act: restoring revokes every session, and reopening one needs the password (and the TOTP code). Users are asked to revoke such devices again (residual risk 20).
- Malware on a device in use is out of scope: it sees what the user sees.

### 3.5 Former member of a channel, group or server

- After the commit that removes them, a former member has no key for later epochs and cannot decrypt new messages or call media.
- They keep what their devices already received. Nothing can revoke that.
- Between the kick and the removal commit they are still in the group, but the server no longer delivers to them (see 3.3 for the case of a colluding server).
- A banned user cannot rejoin with the same account. A new account needs a new instance invitation.

### Out of scope

- Compromise of the build or update pipeline (mitigated by signed updates and reproducibility efforts, addressed at M8–M9).
- Side channels on the device, physical coercion, a malicious participant recording a conversation they are part of.
- Traffic analysis resistance and anonymity. Tavern does not hide who talks to whom from the instance.
- Denial of service against the instance.

## 4. What the server sees

### Visible to the server (v1)

| Data | Why |
|---|---|
| Account id, **handle** | Login, invitations, lookup |
| **Profile: display name, avatar, banner, bio, custom status** | Stored in clear in v1; encryption planned in [ADR 0008](adr/0008-encrypted-profiles.md) |
| **Names of servers, channels, categories and roles**, role colours and permissions, channel order | Needed for permissions and invitations |
| Server nicknames | Treated like profile data |
| Device ids, device public keys and certificates, KeyPackages, creation and last-seen times | Authentication Service role |
| Friend list, pending requests, blocks, and the requests a blocked user sent to their blocker, which the blocker never sees ([ADR 0020](adr/0020-friends-and-blocks.md)) | Enforced server side |
| Membership of servers, channels, private groups and DMs; public MLS tree of each group | Routing and permission checks |
| For each message: conversation, sending device, time, padded size, MLS epoch, whether it is a handshake or application message | Delivery Service role |
| For each blob: size, uploader, conversation, time | Access control and quotas |
| Presence (online, idle, do not disturb), typing indicators | Relayed in clear; "invisible" is shown as offline to others but the server knows |
| Who is in which call, when, for how long, track kinds and bitrates, client IP addresses | LiveKit signalling is TLS only |
| Invitation codes (hashed), who invited whom | Closed registration |
| Moderation actions: who kicked or banned whom, and when | Enforced server side |
| Security notices: that an account's password, recovery key, TOTP or device list changed, when, and which devices dismissed the notice | The server performs these changes; it stores a kind and a date so that offline devices are told ([ADR 0016](adr/0016-security-notices.md)) |
| For each device, the server's part of its local store key | Useless without the part derived from the user's root secret; erased at revocation ([ADR 0017](adr/0017-device-identity-and-sign-out.md)) |
| IP addresses of connections | Inherent; not written to the database, and not logged at the default log level |

### Never visible to the server

| Data | How it is protected |
|---|---|
| Message text, edits, deletions, replies, mentions | MLS application messages |
| **Reactions** | MLS application messages |
| **Custom emojis** (images and names), including animated ones | Encrypted blobs and MLS messages. Only handles, the names of servers, channels, categories and roles, and profiles are visible in v1; custom emojis stay end-to-end encrypted |
| Attachments, thumbnails, file names, MIME types, dimensions | Encrypted on the client; metadata inside the MLS message |
| Link previews | Generated on the client, sent inside the message |
| Audio, video, screen share, call data packets | Frame encryption with MLS-derived keys |
| Passwords | OPAQUE |
| Account identity private keys, device private keys, group secrets, media keys | Never leave devices unwrapped |
| Names and icons of private groups | Sent as application messages |
| Device names | Encrypted to the user's own devices |
| Ban and kick reasons, if entered | Sent as application messages to the remaining members |
| Search queries and the search index | Local only |

Rule: a feature that would require the server to read content is redesigned on the client or refused. It is never shipped "temporarily" in clear.

## 5. Residual risks accepted in v1

1. **Metadata is visible** to the instance admin: social graph, activity times, server structure. Mitigation: self-hosting among people who trust the admin; message padding to size buckets.
2. **Profiles are stored in clear** (display name, avatar, banner, bio, status). Planned evolution: [ADR 0008](adr/0008-encrypted-profiles.md).
3. **The server is the Authentication Service.** Without safety number verification, a malicious server can substitute an identity key in a first contact. Mitigation: key pinning, change warnings, safety numbers and QR codes.
4. **Server channels trust server-side roles** for who may join. A malicious server can authorise a ghost member for future messages; the arrival is always shown. DMs, private groups and private channels are not affected.
5. **Window between a kick and its removal commit.** Delivery is cut at once; the cryptographic removal waits for the first online member device. A colluding server could exploit the window.
6. **Spurious removals** by the server through the external sender key or by refusing delivery: denial of service only. Likewise, by changing the version byte of a wrapped root secret, a server can make a sign-in fail with the calm "account too old" message instead of the alarm about keys that do not match; the client accepts no key either way.
7. **Loss or change of the MLS external sender key** disables server-initiated removals in existing groups until a member device repairs each group; see [ADR 0002](adr/0002-mls-via-openmls.md#external-sender-key-lifecycle). The key is dedicated to this purpose, separate from every other instance secret, and included in backups.
8. **Offline password guessing** after a full server compromise, at Argon2id cost. A cracked password exposes the wrapped account root secret, allowing device enrolment as that user, and, with a seized signed-out computer of that user, the reading of its local store. Mitigations: the client refuses weak passwords at registration and password change (minimum length and strength estimate), every enrolment is notified to all existing devices of the account, and contacts see a notice in shared conversations. TOTP does not protect against this, since it is enforced by the server.
9. **LiveKit signalling is not end-to-end encrypted.** Call membership, timing and volumes are visible to the SFU. Codec headers needed for routing are not encrypted.
10. **Members of a DM or group who are not in a call** hold the exporter secret from which that call's keys derive.
11. **Prebuilt libwebrtc.** The LiveKit SDK downloads a binary WebRTC build at compile time. It processes plaintext media before encryption. Mitigation: exact version pinning, restricted sources in `deny.toml`, review on each upgrade. A build from source is an option for M9.
12. **No history for new members or new devices** ([ADR 0006](adr/0006-no-prior-history-v1.md)); losing all devices loses the history. The UI says so; a remedy for a user's own devices is proposed in [ADR 0009](adr/0009-history-on-new-devices.md).
13. **Deleted messages** disappear from honest clients only. Ciphertext already delivered cannot be recalled.
14. **Compromised device**: full access to that device's history and identity until revoked.
15. **Dependencies before 1.0** (OpenMLS, LiveKit Rust SDK): no independent audit of Tavern's integration. The M9 milestone reviews this model, adds fuzzing and audits dependencies.
16. **No TURN by default.** A client on a network that blocks UDP and non-HTTPS TCP cannot join calls unless the admin enables the optional TURN/TLS setup. This is an availability limit, not a confidentiality one.
17. **Advisory RUSTSEC-2026-0387 accepted with justification.** `crypto-bigint` 0.5, a transitive dependency of `opaque-ke`, has known timing variability and no compatible fix. Its affected arithmetic is not linked into Tavern's binaries (our suite uses ristretto255 through `curve25519-dalek`), which CI verifies on every run. See [ADR 0011](adr/0011-account-identity-and-primitives.md).
18. **Security notices can be withheld or dismissed.** They are stored and delivered by the server, so a compromised server can suppress them: they protect against someone who obtained credentials, not against the instance. And for the two kinds shown to devices enrolled afterwards (TOTP disabled by an administrator, account recovered), whoever holds a session of the account can acknowledge the notice, which hides it from devices enrolled later. Devices that existed when the event happened keep showing it until dismissed on each of them. See [ADR 0016](adr/0016-security-notices.md).
19. **OpenSSL in the client** (Windows and Linux): SQLCipher encrypts the local store with OpenSSL's symmetric primitives, compiled into the client; macOS uses the system's CommonCrypto. Any OpenSSL advisory requires a new client release; `cargo deny` watches `openssl-src` through RustSec on every CI run. Only `libcrypto`'s ciphers and hashes are reached, never TLS or certificate parsing. Nothing else in Tavern may use OpenSSL (`deny.toml`, CI). See [ADR 0018](adr/0018-local-store-encryption.md).
20. **A restored backup brings back revoked devices.** The database of the backup lists as active every device revoked since. Restoring revokes every session and records a notice for every account ([ADR 0019](adr/0019-mls-direct-messages.md), section 15), so such a device can act again only with the user's password (and TOTP); until the user revokes it again, someone holding both the device and the password can use it without a "new device" notice to the other devices, which they could not have avoided anyway by enrolling a new device with that password. Messages sent after the backup are lost and every conversation is recreated.
21. **KeyPackage exhaustion by a friend.** A friend may claim a user's KeyPackages, each one-time package once. Claiming them all would leave a device that is offline with its last-resort package only, which every new conversation would then share until the device replaces it. The claims of another user's packages are limited to 3 an hour and 10 a day per pair (60 an hour per requester), so emptying an offline device's 20 one-time packages takes days, not hours. The counters are kept in memory and start from zero when the server restarts ([ADR 0019](adr/0019-mls-direct-messages.md), section 3).

## 6. Engineering rules that follow

- No cryptographic primitive is implemented in this repository; OpenMLS, RustCrypto, `rustls` and `opaque-ke` provide them.
- Secrets are zeroised after use. Secrets, tokens, keys, ciphertext and plaintext are never logged.
- Every network input is validated, bounded in size and subject to timeouts; protocol decoders are fuzzed.
- A panic caused by a network input fails that request or that connection, never the server: the server is built with `panic = "unwind"`, a REST request whose handler panics gets `500 INTERNAL`, a gateway frame whose handling panics closes its connection (1011), and the log says where the panic happened, never its message, not even through a blocking task's error ([ADR 0019](adr/0019-mls-direct-messages.md), section 18). Otherwise any panic reachable from a client would be a way to stop the instance.
- The server crate uses `crypto` for validation only. A test at M2 asserts that the database contains no plaintext after a conversation between two clients.
- No telemetry and no third-party service: no analytics, external CDN or remote fonts.
