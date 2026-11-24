# Protocol

This document specifies how a Tavern client talks to a Tavern server: the REST API used for authentication and provisioning, the WebSocket gateway used for everything real-time, versioning rules, error codes and limits. It covers milestones **M1** (accounts) and **M2** (friends and encrypted DMs). Later milestones extend it.

Status: design. The `.proto` excerpts below are the reference for `crates/protocol/proto/`; field numbers may still change until M1 ships.

## 1. Transports

| Transport | Use | Encoding |
|---|---|---|
| HTTPS REST, prefix `/v1` | Authentication, account, devices, KeyPackages, friends, conversation creation, blobs, administration | JSON, binary fields as unpadded base64url; documented with OpenAPI |
| WebSocket gateway, `/gateway/v1` | Session, message delivery, MLS handshake messages, presence, typing, events | Protobuf (proto3), one message per binary frame |

The split follows one rule: request/response operations that are infrequent go through REST; everything pushed by the server or sent at interactive rates goes through the gateway ([ADR 0005](adr/0005-protobuf-protocol.md)).

All traffic uses TLS. REST requests after login carry `Authorization: Bearer <session token>`. The gateway authenticates with its first frame, so the token never appears in a URL.

## 2. Versioning

- The gateway major version is in the path (`/gateway/v1`), in the WebSocket subprotocol (`tavern.v1`) and in the protobuf package (`tavern.gateway.v1`). REST has its own major version in the path.
- `GET /version` returns the server version, the range of gateway major versions it serves, and the current **minor** protocol number.
- Within a major version, changes are additive only:
  - new messages, new fields, new enum values, new `oneof` members;
  - field numbers and enum values are never reused or renumbered; removed ones are marked `reserved`;
  - no field changes type or meaning.
- Receivers ignore unknown fields. A frame whose `oneof payload` is unset (an unknown member for that receiver) is answered with `UNSUPPORTED_MESSAGE` by the server, and ignored by the client when it is an event.
- `Hello` and `Ready` exchange minor numbers; each side uses only features both understand.
- A breaking change creates `tavern.gateway.v2` and `/gateway/v2`. A server serves at least the previous major version for one release cycle.
- Message content inside MLS (`tavern.content.v1`) is versioned separately, because old messages stay in local stores. Clients render an unknown content type as "unsupported message, please update".

## 3. Gateway envelope

```proto
syntax = "proto3";
package tavern.gateway.v1;

// Client → server.
message ClientFrame {
  // Chosen by the client, unique per connection, never 0.
  // Echoed in the response.
  uint64 request_id = 1;

  oneof payload {
    Hello hello = 10;
    Heartbeat heartbeat = 11;
    AckDeviceList ack_device_list = 12;

    // M2
    SendMessage send_message = 20;
    SubmitCommit submit_commit = 21;
    FetchMessages fetch_messages = 22;
    AckMessages ack_messages = 23;
    AckWelcome ack_welcome = 24;
    FetchGroupInfo fetch_group_info = 25;
    SetPresence set_presence = 30;
    SetTyping set_typing = 31;
  }
}

// Server → client.
message ServerFrame {
  // Copy of the request id for a response; 0 for an event.
  uint64 request_id = 1;

  oneof payload {
    Error error = 9;
    Ready ready = 10;
    HeartbeatAck heartbeat_ack = 11;

    Ack ack = 12;

    // M1 events
    SessionRevoked session_revoked = 15;
    DeviceListChanged device_list_changed = 16;
    SecurityNotice security_notice = 17;

    // M2 responses
    SendMessageAck send_message_ack = 20;
    CommitAck commit_ack = 21;
    MessageBatch message_batch = 22;
    GroupInfo group_info = 25;

    // M2 events
    MessageEvent message_event = 40;
    CommitEvent commit_event = 41;
    ProposalEvent proposal_event = 42;
    WelcomeEvent welcome_event = 43;
    ConversationCreated conversation_created = 44;
    FriendshipChanged friendship_changed = 45;
    PresenceChanged presence_changed = 46;
    TypingEvent typing_event = 47;
    KeyPackagesLow key_packages_low = 48;
    UserDevicesChanged user_devices_changed = 49;
    JoinConversation join_conversation = 50;
  }
}
```

Rules:

- Every `ClientFrame` gets exactly one `ServerFrame` with the same `request_id`: the specific response, a generic `Ack`, or an `Error`.
- Events have `request_id = 0` and need no reply, except where an explicit acknowledgement message exists (`AckMessages`, `AckWelcome`).
- Identifiers are UUIDv7, carried as 16 raw bytes. Timestamps are milliseconds since the Unix epoch, assigned by the server.
- Fields named `mls_*` contain MLS wire format (`MLSMessage`, TLS-serialised) and are opaque to the gateway layer.

### Connection lifecycle

1. The client opens `wss://<instance>/gateway/v1` with subprotocol `tavern.v1`.
2. It sends `Hello` within 10 seconds, otherwise the server closes with 4001.
3. The server answers `Ready`, or `Error` followed by a close.
4. The client sends `Heartbeat` every 30 seconds. The server closes a connection that has been silent for 75 seconds.
5. On every `Heartbeat` the server checks that the session is still valid, and closes with 4003 when it is not. `Ready` lists the devices enrolled while this device was away; the client shows them, then sends `AckDeviceList`. `Ready` also lists the security notices this device has not acknowledged; the client shows them until the user dismisses them, then sends `AckSecurityNotices`.
6. From M2: after `Ready`, the client catches up: for each conversation, `FetchMessages` from its last acknowledged sequence number. Pending welcomes are re-sent by the server as `WelcomeEvent` until acknowledged. A Welcome may therefore arrive twice: the connection subscribes to events before `Ready`, so that none is lost, and a Welcome stored in between is both pushed and re-sent. The client goes by `welcome_id`: a Welcome it already acknowledged is ignored, and so is a Welcome for a group it has already joined, even one it has not acknowledged yet (the join was written, the acknowledgement lost); it acknowledges that one again.
7. On disconnect the client reconnects with exponential backoff and jitter (1 s up to 60 s). It does not reconnect after 4002 or 4003: the session is gone and the user must log in again. After 4009 (it did not keep up with its events) it reconnects and catches up as in step 6.

Pushed events are notifications, not a reliable source. An event may be missed (the connection dropped, or its queue was full: the server then closes with 4009 rather than drop an event in silence) and events may arrive out of order (each request notifies after its own transaction). The source is the stored sequence, and from M2 the client follows one rule: it processes each conversation's sequence in the order of its numbers, from the last one it processed. Given an event with number N+2 when it has processed N, it puts N+2 aside, fetches the gap with `FetchMessages` (after N), and processes N+1, then N+2. Welcomes, security notices and the device list come back at each connection.

One connection per device. A second connection with the same session closes the first (4004).

## 4. Messages for M1 (accounts)

### 4.1 REST

The authoritative description is the OpenAPI document served at `GET /v1/openapi.json`. Summary:

| Method and path | Purpose | Auth |
|---|---|---|
| `GET /health` | Liveness and database check | none |
| `GET /version` | Server version, protocol versions, MLS external sender public key, source link, build commit (`commit`, when the build recorded it; `-dirty` suffix for uncommitted changes) | none |
| `GET /v1/openapi.json` | OpenAPI description | none |
| `POST /v1/auth/register/start` | Invite code, handle, OPAQUE `RegistrationRequest` → `RegistrationResponse`, suite | none |
| `POST /v1/auth/register/finish` | Invite code, handle, display name, OPAQUE `RegistrationUpload`, AIK public key, two wrapped copies of the account root secret → user id | none |
| `POST /v1/auth/login/start` | Handle, OPAQUE `CredentialRequest` → login id, `CredentialResponse`, suite | none |
| `POST /v1/auth/login/finish` | Login id, OPAQUE `CredentialFinalization` → grant, or `totp_required` | none |
| `POST /v1/auth/login/totp` | Login id, TOTP code or recovery code → grant | none |
| `POST /v1/auth/logout` | End the current session | session |
| `POST /v1/devices` | Device certificate, encrypted device name, platform → session | enrolment token |
| `POST /v1/devices/{id}/session` | Signature of the session nonce by the device key → session | enrolment token |
| `GET /v1/devices` | Active devices of the account | session |
| `DELETE /v1/devices/{id}` | Revoke a device and its session | session |
| `GET /v1/users/me` | The signed-in account | session |
| `POST /v1/account/totp/enable`, `/confirm`, `/disable` | TOTP enrolment | session |
| `POST /v1/auth/reauth/start`, `/finish` | A full OPAQUE login from an existing session (plus the TOTP code when enabled) → re-authentication token, challenge, wrapped root secret | session |
| `POST /v1/account/password/start`, `/finish` | Change the password: OPAQUE registration of the new one, new "password" wrapped copy, AIK signature | session + re-authentication token |
| `POST /v1/account/recovery-key` | Replace the recovery key: new "recovery" wrapped copy, AIK signature | session + re-authentication token |
| `POST /v1/auth/recover/start` | Handle, OPAQUE `RegistrationRequest` for the new password → challenge, AIK public key, "recovery" wrapped copy, `RegistrationResponse` | none |
| `POST /v1/auth/recover/finish` | OPAQUE `RegistrationUpload`, new "password" wrapped copy, AIK signature → 204 | none |
| `POST /v1/admin/invites`, `GET`, `DELETE /v1/admin/invites/{id}` | Instance invitations | admin session |
| `GET /v1/admin/users` | Accounts of the instance | admin session |
| `POST /v1/admin/users/{id}/disable`, `/enable` | Disable or re-enable an account | admin session |
| `POST /v1/admin/users/{id}/totp/disable` | Disable the TOTP of a user who lost their authenticator and codes | admin session |

Credential changes are described in [ADR 0003](adr/0003-opaque-authentication.md#credential-changes). In short:

- Each one is authorised by a signature of the account identity key over a single-use challenge, the handle and the new values. A refused change answers `INVALID_PROOF`, whatever the reason.
- A re-authentication token authorises one change, for five minutes, in the session that obtained it.
- **Password change**: every other session of the account ends (`SessionRevoked`, reason `CREDENTIALS_CHANGED`); the calling device stays signed in.
- **Recovery**: every session ends. TOTP stays enabled. For an unknown handle `recover/start` returns decoys with the same shape, stable across requests; `recover/finish` can then never succeed.
- **Recovery key rotation**: the previous recovery key stops working at once.

Notes:

- A **grant** is what a completed login returns: an enrolment token and a session nonce (both single use, five minutes), the account's public identity key and the wrapped "password" copy of its account root secret. The wrapped copy is never returned before the TOTP step when TOTP is enabled.
- The two routes that open a session (`POST /v1/devices`, `POST /v1/devices/{id}/session`) answer with the session token, its expiry and, since REST 1.2, `local_store_share`: the server's 32-byte part of the key that wraps this device's local store. It is created with the device's first session, never changes, is returned to that device only, and is erased when the device is revoked ([ADR 0017](adr/0017-device-identity-and-sign-out.md)). The wrapped copies hold the account root secret (format version 2) since REST 1.2.
- The enrolment token is sent as `Authorization: Bearer`, like a session token. It is consumed by the request that uses it, successful or not.
- A session always belongs to a device. A device whose session ended logs in again and reopens it with `POST /v1/devices/{id}/session`; it is not enrolled a second time.
- Handles must be sent in canonical form (lower case ASCII `a–z 0–9 _ .`, 2 to 32 characters, no leading, trailing or double dot). The server refuses anything else with `INVALID_HANDLE`; it never lower-cases or trims. A handle cannot be changed in v1.
- Login for an unknown handle returns a well-formed OPAQUE response computed from a decoy record. Failures at `login/finish` return the same `INVALID_CREDENTIALS` whatever the cause. `ACCOUNT_DISABLED` is returned only after the right password.
- `HANDLE_TAKEN` is returned by `register/start` only to a caller holding a valid invitation code.
- `/v1/auth/*` is limited to 30 requests per minute per client address, and login, registration and recovery starts to 5 per minute per handle.
- The first administrator invitation is created on the host by `deploy/scripts/create-admin.sh`.
- Password strength is checked by the client only (at least 12 characters and a zxcvbn-style score of 3 or more), at registration and password change; the server cannot see the password.

### 4.2 Gateway

```proto
message Hello {
  bytes session_token = 1;
  uint32 protocol_minor = 2;
  string client_version = 3;   // e.g. "0.1.0"
  string client_platform = 4;  // "windows" | "macos" | "linux"
}

message Ready {
  bytes user_id = 1;
  bytes device_id = 2;
  uint32 protocol_minor = 3;
  uint64 server_time_ms = 4;
  Limits limits = 5;
  bytes mls_external_sender_key = 6;  // current Ed25519 public key
  // One-time KeyPackages of this device the server can still serve. Since
  // minor 2.
  uint32 key_packages_remaining = 7;
  // Devices enrolled since this device last sent AckDeviceList.
  repeated DeviceSummary new_devices = 8;
  // Security notices this device has not acknowledged, oldest first, at
  // most 32. Since minor 1.
  repeated SecurityNotice security_notices = 9;
}

message DeviceSummary {
  bytes device_id = 1;
  Platform platform = 2;
  uint64 created_at_ms = 3;
}

// The user has seen the device list. Answered with Ack.
message AckDeviceList {}

message Limits {
  uint32 max_frame_bytes = 1;
  uint32 max_application_message_bytes = 2;
  uint64 max_upload_bytes = 3;
  uint32 heartbeat_interval_ms = 4;
}

message Heartbeat {}
message HeartbeatAck { uint64 server_time_ms = 1; }

message Ack {}

message Error {
  ErrorCode code = 1;
  string message = 2;          // English, for logs; UIs localise from the code
  uint32 retry_after_ms = 3;   // set for RATE_LIMITED and UNAVAILABLE
  uint64 current_epoch = 4;    // set for STALE_EPOCH when known (since minor 5)
}

// The session of this device ended. The server closes the connection next
// (4003, or 4004 when replaced by a newer connection of the same device).
message SessionRevoked { RevocationReason reason = 1; }
// REVOKED | CREDENTIALS_CHANGED | ACCOUNT_DISABLED | REPLACED

// A device of the account was enrolled (added) or revoked. Sent to every
// other connected device of the account. For an enrolment the client notifies
// the user and offers to revoke the new device.
message DeviceListChanged {
  bytes device_id = 1;
  bool added = 2;
}

// Something security-relevant happened to the account. Sent as an event to
// the connected devices, and listed in Ready for every device that has not
// acknowledged it. A kind and a date, never text.
message SecurityNotice {
  SecurityNoticeKind kind = 1;
  bytes notice_id = 2;        // since minor 1
  uint64 created_at_ms = 3;   // since minor 1
}
// TOTP_DISABLED_BY_ADMIN | PASSWORD_CHANGED | ACCOUNT_RECOVERED
// | DEVICE_REVOKED | RECOVERY_KEY_REPLACED

// The user dismissed these notices on this device. At most 64 identifiers;
// unknown ones are ignored. Answered with Ack. Since minor 1.
message AckSecurityNotices { repeated bytes notice_ids = 1; }
```

#### Security notices

Minor version 1 of the gateway. Each event below is stored for the account and reaches every device that existed when it happened, whether it was connected or not ([ADR 0016](adr/0016-security-notices.md)):

| Kind | Recorded when | Not shown to | Pushed to connected devices |
|---|---|---|---|
| `TOTP_DISABLED_BY_ADMIN` | An administrator disables the account's TOTP | nobody | yes |
| `PASSWORD_CHANGED` | The password is changed | the device that changed it | no: they are signed out, and read it from `Ready` after signing in again |
| `ACCOUNT_RECOVERED` | The recovery key is used to set a new password | nobody | no: every device is signed out |
| `DEVICE_REVOKED` | A device of the account is revoked | the device that revoked it | yes |
| `RECOVERY_KEY_REPLACED` | The recovery key is replaced | the device that replaced it | yes |

- A device acknowledges for itself only: a notice dismissed on one device stays on the others.
- A device is not told about what happened before it was enrolled. Exception: `TOTP_DISABLED_BY_ADMIN` and `ACCOUNT_RECOVERED` are also listed for devices enrolled later, until one device of the account acknowledges them.
- Enabling TOTP again deletes the `TOTP_DISABLED_BY_ADMIN` notices of the account.
- A notice is listed for 90 days at most.
- A client shows a kind it does not know as a generic notice; it never drops it.
- A notice without `notice_id` (a server older than minor 1) cannot be acknowledged and is not shown.
- Enrolments are not notices: they use `Ready.new_devices` and `DeviceListChanged`, which carry the device to revoke.

## 5. Messages for M2 (friends and encrypted DMs)

### 5.1 REST

| Method and path | Purpose |
|---|---|
| `POST /v1/devices/me/key-packages` | Upload up to 100 one-time KeyPackages of this device and, optionally, a new last-resort KeyPackage, which replaces the current one. Each must be valid now, for at most 90 days, and carry the key and certificate the device enrolled with (`INVALID_KEY_PACKAGE` otherwise: one refused package refuses the upload). A package sent again is stored once, and never again once it was served (its reference stays taken until it expires); a device keeps at most 200. Returns the count below. Implemented (task 5 of M2) |
| `GET /v1/devices/me/key-packages/count` | One-time KeyPackages of this device the server can still serve. Implemented |
| `POST /v1/users/{user_id}/key-packages/claim` | One KeyPackage for each active device of the user, the requesting device excepted: the oldest one-time package, deleted in the claiming transaction (two claims at once never get the same one), or the last-resort package, kept, when none is left. A device with neither is absent from the answer: it joins later by external commit. The device certificate travels in each package's credential. Allowed for one's own user, and for a friend; anyone else, an unknown user included, gets `FORBIDDEN`, and nothing is consumed. Rate limits below. Implemented |
| `GET /v1/users/{id}/devices` | Device ids, signature keys and certificates of a user |
| `GET /v1/friends` | Friends, requests received, requests sent, and users blocked; each with id, handle, display name, identity key and date. Implemented (task 6 of M2, [ADR 0020](adr/0020-friends-and-blocks.md)) |
| `POST /v1/friends/requests` | Send a request by handle: `request_sent`, or `friends` when it crosses a request from that user. `NOT_FOUND` for an unknown handle, `BLOCKED` when the sender blocks that user, `ALREADY_EXISTS` between friends; sending again changes nothing (one request per pair). A request to a user who blocks its sender looks sent and stays its sender's alone. At most 20 an hour per user *. Implemented |
| `POST /v1/friends/requests/{user_id}/accept`, `DELETE /v1/friends/requests/{user_id}` | Accept (the recipient), decline (the recipient) or cancel (the sender). Implemented |
| `DELETE /v1/friends/{user_id}` | Remove a friend. Implemented |
| `PUT /v1/blocks/{user_id}`, `DELETE /v1/blocks/{user_id}` | Block (ends a friendship or a request between the two; not disclosed to the blocked user), unblock (deletes what the blocked user sent meanwhile). Implemented |
| `POST /v1/conversations` | Create the DM with a friend (`{"user_id": ...}`); idempotent: one DM per pair of users, `201` when created, `200` with the existing one (with its epoch) if any, also when two creations cross and when two users become friends again. `NOT_FRIENDS` for anyone else, an unknown user and a blocked or blocking one alike; `INVALID_ARGUMENT` for oneself. Implemented (task 7 of M2) |
| `GET /v1/conversations` | Conversations of the user, oldest first: members, generation and current epoch of the MLS group (`null` while it has none), last sequence number, `read_only` for a DM whose users are not friends any more, and `joined`: whether the requesting device is in its group and not being removed from it (`false` for a device left out of the group, which joins by external commit, and for a device the server is removing). `joined` since task 9 of M2 (a field, not a route: the REST minor is unchanged). Implemented |

Creating a DM reserves a conversation id on the server, and announces it (`ConversationCreated`). The creating device then builds the MLS group locally (group id = conversation id followed by a 32-bit group generation, 0 at first, incremented when the group is recreated; `external_senders` = the server's key), adds its own other devices and the peer's devices, and submits the first commit with its Welcome. If it stops before, the conversation stays without a group (epoch `null`): any active device of either user may create it, the first commit for epoch 0 wins and the others get `STALE_EPOCH`. Details, including unfriending, blocking and recreation: [ADR 0019](adr/0019-mls-direct-messages.md).

### 5.2 Gateway: messages and MLS

```proto
// An MLS PrivateMessage carrying application content.
message SendMessage {
  bytes conversation_id = 1;
  bytes client_message_id = 2;  // UUID, idempotency key per device
  bytes mls_message = 3;
}

message SendMessageAck {
  uint64 seq = 1;
  uint64 server_time_ms = 2;
}

// An MLS commit (PublicMessage). Accepted only if `epoch` is the group's
// current epoch; exactly one commit is accepted per epoch.
message SubmitCommit {
  bytes conversation_id = 1;
  uint64 epoch = 2;
  bytes mls_commit = 3;
  bytes mls_welcome = 4;      // present when the commit adds members
  bytes mls_group_info = 5;   // required: GroupInfo of the new epoch, with ratchet tree
  bool external = 6;          // external commit (a new device joining)
}

message CommitAck {
  uint64 seq = 1;
  uint64 new_epoch = 2;
  uint64 server_time_ms = 3;
}

message FetchMessages {
  bytes conversation_id = 1;
  uint64 after_seq = 2;
  uint32 limit = 3;           // at most 200
}

message MessageBatch {
  repeated StoredMessage messages = 1;
  bool more = 2;
}

message StoredMessage {
  bytes conversation_id = 1;
  uint64 seq = 2;
  uint64 epoch = 3;
  MessageKind kind = 4;       // APPLICATION | COMMIT | PROPOSAL
  bytes sender_device_id = 5; // empty for server-originated proposals
  uint64 server_time_ms = 6;
  bytes mls_message = 7;
}

// The device has durably processed everything up to `up_to_seq`.
message AckMessages {
  bytes conversation_id = 1;
  uint64 up_to_seq = 2;
}

message AckWelcome { bytes welcome_id = 1; }

// Latest GroupInfo of a conversation, for a new device joining by external commit.
message FetchGroupInfo { bytes conversation_id = 1; }
message GroupInfo {
  uint64 epoch = 1;
  bytes mls_group_info = 2;
}

// Events. Each carries one StoredMessage.
message MessageEvent  { StoredMessage message = 1; }
message CommitEvent   { StoredMessage message = 1; }
message ProposalEvent { StoredMessage message = 1; }  // includes external Remove proposals from the server

message WelcomeEvent {
  bytes welcome_id = 1;
  bytes conversation_id = 2;
  bytes mls_welcome = 3;
}

// To the connected devices of the conversation's members. Since minor 4.
message ConversationCreated {
  bytes conversation_id = 1;
  ConversationKind kind = 2;
  repeated bytes member_user_ids = 3;
}

// A friend enrolled or revoked a device. Sent to the connected devices of
// the user's friends (since minor 3). Clients show a notice in shared
// conversations when a device was added.
message UserDevicesChanged {
  bytes user_id = 1;
  bytes device_id = 2;
  bool added = 3;
}

// A claim left this device fewer than 10 one-time KeyPackages: it uploads
// more. A device that is not connected uploads at its next connection.
message KeyPackagesLow { uint32 remaining = 1; }

// This active device of a member is not in the conversation's group, or the
// server is removing it: it joins by external commit. Sent after each commit
// the server merges, in a DM open to writing only, to such devices that are
// connected; the others read `joined` in GET /v1/conversations. Since minor 6.
message JoinConversation { bytes conversation_id = 1; }
```

Delivery rules (implemented in tasks 8 and 9 of M2, gateway minors 5 and 6; restore and recreation come with task 9b):

- Each conversation has one sequence, shared by application messages, proposals and commits, numbered under the lock of the conversation's row: strictly increasing, without gaps. A device processes it in the order of its numbers, whatever the order its events arrive in, and fills a gap with `FetchMessages` (section 3, connection lifecycle). It reads it from the commit that added it to the group, to the commit that removed it if one did (`FetchMessages`, at most 200 a page).
- The group's devices, who receives what, are computed by the server from the public tree it merged, in the same transaction, never from what a client says. A message goes to every device of the group but its sender's, the sender's other devices included; a commit to the devices that held the group before it; a Welcome to each device the commit added, sent again at each connection until `AckWelcome`.
- The server checks, for every message: the device is a current leaf of the group, the conversation-specific authorisation holds, and sizes are within limits. Unknown conversations and conversations of others answer the same `NOT_A_MEMBER`. Under the conversation's lock, `SendMessage` and `SubmitCommit` also check that the sending device may still act: a live session, the device not revoked, its account not disabled (`UNAUTHENTICATED` otherwise). A revocation is in force once it is committed, before its connection closes and before its removals are asked for; and a committer's leaf is checked against the active devices whether or not its commit carries a path.
- A device's session ending (revocation, sign-out, a disabled account, changed credentials) closes its connection at once: `SessionRevoked`, then the close, without waiting for its queue. A request the connection receives once the session ended is not handled, even one sent before the end and still waiting to be read; a request already being handled is answered by its own checks (`UNAUTHENTICATED`).
- A conversation that has no group yet gets it from any active device of either user: the first commit for epoch 0 wins, the others get `STALE_EPOCH` and join by the winner's Welcome.
- A DM whose users are not friends any more is read-only: application messages, any new leaf (Add, external commit) and `FetchGroupInfo` are refused, removals and updates of one's own leaf go through. The GroupInfo is refused because its tree would tell the other user of every change of devices, and an external commit is refused anyway. The user who blocks gets `BLOCKED`; the blocked user gets `NOT_FRIENDS`, the same answer as after an unfriending, by the same work.
- Application messages must be encrypted for the current epoch (`STALE_EPOCH` otherwise) and are refused while removals are pending (`REMOVAL_PENDING`). Both are recovered by the client without user-visible error: it applies or commits what is pending, re-encrypts for the new epoch and resends with the same `client_message_id`. Only repeated failure (three attempts) surfaces as "not sent, retry".
- A commit is announced for the group's current epoch (`STALE_EPOCH` for a past one, `INVALID_COMMIT` for one the group has not reached) and carries a Welcome for exactly the KeyPackages it adds (their `KeyPackageRef`s), and none when it adds no one. A group's first commit, which the server cannot process (it has no state of epoch 0), is checked for its framing: a `PublicMessage` carrying a commit of this group at epoch 0, by the submitting device's leaf. Its Welcome is matched to the tree: for each device the commit adds, the leaf's encryption key is the one of a KeyPackage of that device the server served (a one-time package, or a last resort served at least once, even one its device has replaced since: the server keeps a served package's row until it expires), and the Welcome is for exactly these packages.
- A commit is validated against the public group state: it is the submitting device's own, its signature is valid, the clients' policy holds (proposals allowed for the sender, no group context change, new leaves active devices of participants with valid device certificates and the very key and certificate each device enrolled with), and the GroupInfo submitted with it is the new epoch's (same group context and confirmation tag, with the ratchet tree and `ExternalPub`), signed by the committer. A member's commit that leaves out a pending removal is refused with `REMOVAL_PENDING`; after an external commit, which cannot carry them, the server appends its removals again for the new epoch. The epoch update is atomic ([ADR 0019](adr/0019-mls-direct-messages.md), sections 5, 6 and 14).
- External proposals issued by the server are always `Remove`. Clients reject any other type from an external sender.
- `SendMessage` is idempotent on (`device`, `client_message_id`): a retry returns the original acknowledgement, and a message already accepted is never stored or delivered twice, even re-encrypted. The idempotency record outlives the message, for twice the retention period; a client never resends a message older than the retention period.
- The server deletes a stored message once every device it was for has acknowledged it (every device of the group that reads the sequence at its number, the sender and revoked devices excepted), or after the retention limit (`TAVERN_MESSAGE_RETENTION_DAYS`, default and maximum 30 days), whichever comes first. A welcome is deleted when acknowledged or expired; an idempotency record and a KeyPackage when expired. This purge runs at start-up, then every hour.
- **Removals.** A revoked device, the devices of a disabled account, and a device that has not connected for `TAVERN_DEVICE_INACTIVE_DAYS` (default: the retention; never more), without being revoked, leave each of their groups by one `Remove` proposal of the server, signed with the external sender key and appended to the sequence (`ProposalEvent`, `sender_device_id` empty). A revocation and the disabling of an account ask for them right after their own transaction; the hourly pass asks for any that is missing. A device's activity is its REST requests, its `Hello`s and the heartbeats of its connection, recorded at most once an hour: a device connected for longer than the window is not removed. Asking again changes nothing: one proposal per device and group. Until a member commits it, the group takes no application message (`REMOVAL_PENDING`).
- **The device being removed is cut off** from its proposal on: it is sent the proposal itself, then no event of the conversation; `FetchMessages` gives it the sequence up to its proposal and no further, `AckMessages` stops there, and `SendMessage` and `SubmitCommit` answer `NOT_A_MEMBER`, except an external commit, by which it comes back if it is active again. If the server asks again after an external commit, the cut moves to the new proposal (only commits and proposals lie in between). Once a commit removes the leaf, the device reads up to that commit.
- **A device back from an inactivity** (or a device of an account enabled again) fetches the GroupInfo and rejoins by external commit, as the same device: the commit removes its earlier leaf, which settles its removal, and the server does not ask for it again. The client shows the gap.
- **Devices left out of a group** (decided 2026-11-17): after each commit it merges, in a DM open to writing, the server sends `JoinConversation` to the active devices of either user that are not in the group, or that it is removing. Nothing is stored: `GET /v1/conversations` says `joined: false` to such a device at any time.

### 5.3 Gateway: friends (M2), presence and typing (M3)

`FriendshipChanged` is part of M2. Presence and typing (`SetPresence`, `PresenceChanged`, `SetTyping`, `TypingEvent`) are implemented at the start of M3 (decision of 2026-11-15, to keep M2 on its end criterion); their definitions are kept here because the field numbers are reserved in the envelope.

```proto
message SetPresence { Presence presence = 1; }  // ONLINE | IDLE | DO_NOT_DISTURB | INVISIBLE

// Sent to friends and to members of shared conversations.
// INVISIBLE is reported to others as OFFLINE.
message PresenceChanged {
  bytes user_id = 1;
  Presence presence = 2;
}

// Sent when the user starts typing and every 5 seconds while typing.
message SetTyping { bytes conversation_id = 1; }

// Expires on the client after 8 seconds.
message TypingEvent {
  bytes conversation_id = 1;
  bytes user_id = 2;
}

// To the connected devices of both users, each with their own view of the
// relation. BLOCKED goes to the blocker's devices only. Since minor 3.
message FriendshipChanged {
  bytes user_id = 1;
  FriendshipState state = 2;  // NONE | REQUEST_SENT | REQUEST_RECEIVED | FRIENDS | BLOCKED
}
```

A blocked user receives no presence or typing events from the blocker, and is never told of the block: they see what an unfriending shows. Their friend requests to the blocker are dropped silently: such a request looks sent to them, is never shown to the blocker, and is deleted when the block is lifted ([ADR 0020](adr/0020-friends-and-blocks.md)).

### 5.4 Message content (inside MLS, never seen by the server)

```proto
syntax = "proto3";
package tavern.content.v1;

message Content {
  oneof body {
    Text text = 1;
    Edit edit = 2;        // target message id, new Text
    Delete delete = 3;    // target message id
    // Reactions, attachments, custom emojis, group metadata: M3–M5
  }
}

message Text {
  string markdown = 1;
  bytes reply_to = 2;             // message id, optional
  repeated bytes mentions = 3;    // user ids
  repeated LinkPreview previews = 4;  // generated by the sender's client
}
```

A message id is the pair (conversation id, sequence number); the sender learns it from `SendMessageAck`. The plaintext is padded before encryption to a size bucket: multiples of 256 bytes up to 1 KiB, then 2, 4, 8, 16, 32 and 64 KiB ([ADR 0019](adr/0019-mls-direct-messages.md), section 8).

## 6. Error codes

```proto
enum ErrorCode {
  ERROR_CODE_UNSPECIFIED = 0;

  // Generic
  INVALID_ARGUMENT = 1;       // malformed or out-of-range field
  UNAUTHENTICATED = 2;        // missing, unknown or expired session
  FORBIDDEN = 3;              // authenticated but not allowed
  NOT_FOUND = 4;
  ALREADY_EXISTS = 5;
  PAYLOAD_TOO_LARGE = 6;
  RATE_LIMITED = 7;
  UNSUPPORTED_VERSION = 8;
  UNSUPPORTED_MESSAGE = 9;
  INTERNAL = 10;
  UNAVAILABLE = 11;           // retry later

  // Authentication (M1)
  INVALID_CREDENTIALS = 20;
  INVALID_INVITE = 21;
  HANDLE_TAKEN = 22;
  TOTP_REQUIRED = 23;
  TOTP_INVALID = 24;
  SESSION_REVOKED = 25;
  ACCOUNT_DISABLED = 26;
  INVALID_DEVICE_CERTIFICATE = 27;
  REGISTRATION_EXPIRED = 28;  // start/finish state timed out

  // MLS and delivery (M2)
  // 40 reserved: a commit that loses its epoch gets STALE_EPOCH too
  STALE_EPOCH = 41;           // a message or a commit for a past epoch
  REMOVAL_PENDING = 42;       // commit the pending Remove proposals first
  INVALID_COMMIT = 43;        // failed validation against the public group state
  INVALID_KEY_PACKAGE = 44;
  NOT_A_MEMBER = 45;
  GROUP_INFO_REQUIRED = 46;

  // Social (M2)
  BLOCKED = 60;
  NOT_FRIENDS = 61;
}
```

REST errors carry a JSON body `{ "code": "INVALID_CREDENTIALS", "message": "...", "retry_after_ms": 1200 }` with the matching HTTP status (400, 401, 403, 404, 409, 410, 413, 429, 500, 503). The REST codes are listed in the OpenAPI document (`ErrorCode`); beyond the generic ones they are `INVALID_CREDENTIALS`, `INVALID_INVITE`, `HANDLE_TAKEN`, `INVALID_HANDLE`, `TOTP_REQUIRED`, `TOTP_INVALID`, `ACCOUNT_DISABLED`, `INVALID_DEVICE_CERTIFICATE`, `EXCHANGE_EXPIRED` (410: a two-step exchange timed out or was already used), `TOO_MANY_DEVICES`, `INVALID_PROOF`, `INVALID_KEY_PACKAGE` (400), `BLOCKED` (403: the requester blocks that user) and `NOT_FRIENDS` (403).

WebSocket close codes:

| Code | Meaning |
|---|---|
| 1000 | Normal closure |
| 1009 | Frame too large |
| 4001 | `Hello` not received in time |
| 4002 | Authentication failed |
| 4003 | Session revoked |
| 4004 | Replaced by a newer connection of the same device |
| 4005 | Unsupported protocol version |
| 4006 | Heartbeat timeout |
| 4007 | Rate limit exceeded repeatedly, or `Hello`s too often |
| 4008 | Malformed frame |
| 4009 | The device did not keep up with its events; it reconnects and fetches what it has not read |
| 1011 | The server failed while handling a frame of this connection; the client reconnects |

## 7. Limits

Defaults; those marked * are configurable per instance and announced in `Ready.limits`.

| Item | Limit |
|---|---|
| Gateway frame | 1 MiB * |
| MLS application message (ciphertext) | 65 KiB *: a content of up to 64 KiB, padded (ADR 0019, section 8), plus MLS's overhead, measured at 324 bytes, with the rest of a KiB as margin |
| Text of one message (plaintext) | 4 000 characters, enforced by clients |
| MLS commit | 256 KiB |
| MLS Welcome | 512 KiB |
| MLS GroupInfo | 512 KiB |
| KeyPackage | 4 KiB each, 100 per upload, 200 stored per device; served while valid for more than an hour |
| Friend requests | 20 per hour per requesting user, unknown handles included; exact sliding window, in memory * |
| KeyPackage claims | 60 per hour per requesting user; 3 per hour and 10 per day per (requester, target), claims of one's own devices not counted. Exact sliding windows, counted in memory: they start from zero when the server restarts * |
| REST JSON body | 64 KiB (512 KiB for KeyPackage upload) |
| Attachment (M5) | 500 MB * |
| Handle | 2–32 characters, `a–z 0–9 _ .`, lower case, unique |
| Display name | 1–64 characters |
| Devices per account | 10 |
| `Hello` deadline | 10 s |
| Heartbeat interval / timeout | 30 s / 75 s * |
| OPAQUE login state | 60 s |
| Pending TOTP step | 5 min, 5 wrong codes |
| Enrolment token | 5 min |
| `FetchMessages` page | 200 messages |
| Security notices | 32 listed in `Ready`, 64 identifiers per `AckSecurityNotices`, kept 90 days |
| Gateway requests per device | 30 per 10 s sustained, burst 60, every frame after `Hello` counted, across the device's connections: reconnecting gives no new budget |
| Gateway `Hello`s per device | 10 per minute; beyond, `RATE_LIMITED` and a close with 4007 |
| Gateway events queued per connection | 32; beyond, the connection is closed with 4009 once it has sent them |
| Typing updates | 1 per 3 s per conversation |
| Auth routes | 30 per minute per client address, 5 per minute per handle |
| Stored message retention | until acknowledged by all recipient devices, at most 30 days * |
| Device inactivity before removal from groups | the retention period, never more * |
| Password (client-enforced) | at least 12 characters, strength score ≥ 3 of 4 |

Exceeding a size limit yields `PAYLOAD_TOO_LARGE`; exceeding a rate yields `RATE_LIMITED` with `retry_after_ms`. A gateway connection that keeps exceeding its rate (ten requests refused in a row) is closed with 4007, and so is a `Hello` beyond its limit, after its `RATE_LIMITED` answer.

## 8. Security requirements on implementations

- Decoders treat every input as hostile: bounded allocation, no recursion on attacker-controlled depth, strict length checks before copying.
- Neither side logs tokens, keys, `mls_*` fields or decrypted content.
- The client verifies `mls_external_sender_key` from `Ready` against the `external_senders` extension of each group and repairs mismatches as described in [ADR 0002](adr/0002-mls-via-openmls.md#external-sender-key-lifecycle).
- The gateway and certificate decoders, and the server's checks of an uploaded KeyPackage, are fuzz targets (`crates/protocol/fuzz`, run weekly and on demand by `.github/workflows/fuzz.yml`); encode/decode round trips are property tested.
