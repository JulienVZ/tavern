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

    // M1 events
    SessionRevoked session_revoked = 15;
    DeviceListChanged device_list_changed = 16;

    // M2 responses
    SendMessageAck send_message_ack = 20;
    CommitAck commit_ack = 21;
    MessageBatch message_batch = 22;
    Ack ack = 23;
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
5. After `Ready`, the client catches up: for each conversation, `FetchMessages` from its last acknowledged sequence number. Pending welcomes are re-sent by the server as `WelcomeEvent` until acknowledged.
6. On disconnect the client reconnects with exponential backoff and jitter (1 s up to 60 s).

One connection per device. A second connection with the same session closes the first (4004).

## 4. Messages for M1 (accounts)

### 4.1 REST

| Method and path | Purpose | Auth |
|---|---|---|
| `GET /health` | Liveness and database check | none |
| `GET /version` | Server version, protocol versions, MLS external sender public key, source link | none |
| `POST /v1/auth/register/start` | Invite code, handle, OPAQUE `RegistrationRequest` → `RegistrationResponse`, registration id | none |
| `POST /v1/auth/register/finish` | Registration id, OPAQUE `RegistrationUpload`, AIK public key, two wrapped AIK copies → user id | none |
| `POST /v1/auth/login/start` | Handle, OPAQUE `CredentialRequest` → `CredentialResponse`, login id | none |
| `POST /v1/auth/login/finish` | Login id, OPAQUE `CredentialFinalization` → enrolment token and wrapped AIK, or `TOTP_REQUIRED` | none |
| `POST /v1/auth/login/totp` | Login id, TOTP code → enrolment token and wrapped AIK | none |
| `POST /v1/auth/recover/start`, `/finish` | Password reset with the recovery key: fetch the recovery-wrapped AIK, prove possession by signing a challenge with the AIK, register a new OPAQUE record | none |
| `POST /v1/devices` | Device certificate, encrypted device name → device id, session token | enrolment token |
| `GET /v1/devices` | List own devices | session |
| `DELETE /v1/devices/{id}` | Revoke a device and its session | session |
| `POST /v1/auth/logout` | Revoke the current session | session |
| `POST /v1/account/password` | Change password: new OPAQUE registration and new password-wrapped AIK | session, plus a fresh OPAQUE login |
| `POST /v1/account/totp/enable`, `/confirm`, `/disable` | TOTP enrolment | session |
| `GET /v1/users/me`, `PATCH /v1/users/me` | Own account and profile | session |
| `GET /v1/users/{id}`, `GET /v1/users/by-handle/{handle}` | Public profile and AIK public key | session |
| `POST /v1/admin/invites`, `GET`, `DELETE /v1/admin/invites/{id}` | Instance invitations | admin session |
| `GET /v1/admin/users`, `PATCH /v1/admin/users/{id}` | List, disable, set quotas | admin session |

Notes:

- The enrolment token is valid for 5 minutes and for `POST /v1/devices` only. A session always belongs to a device.
- Login for an unknown handle returns a well-formed OPAQUE response computed from a dummy record. Failures at `login/finish` return the same `INVALID_CREDENTIALS` error whatever the cause.
- All `/v1/auth/*` routes are rate limited per IP and per handle.
- The first admin account and the first invitation are created on the host by `deploy/scripts/create-admin.sh`.
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
  uint32 key_packages_remaining = 7;
}

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
  uint64 current_epoch = 4;    // set for EPOCH_CONFLICT and STALE_EPOCH
}

// The session was revoked (logout elsewhere, device removed, account disabled).
// The server closes the connection right after.
message SessionRevoked { RevocationReason reason = 1; }

// One of the user's own devices was added or revoked. Sent to every other
// device of the account; clients show a notification with a revoke action
// when a device was added.
message DeviceListChanged {
  bytes device_id = 1;
  bool added = 2;
}
```

## 5. Messages for M2 (friends and encrypted DMs)

### 5.1 REST

| Method and path | Purpose |
|---|---|
| `POST /v1/devices/me/key-packages` | Upload a batch of KeyPackages and, optionally, a new last-resort KeyPackage |
| `GET /v1/devices/me/key-packages/count` | Remaining one-time KeyPackages |
| `POST /v1/users/{id}/key-packages/claim` | One KeyPackage per active device of the user, each with its device certificate. One-time packages are deleted when claimed; the last-resort package is returned when none is left |
| `GET /v1/users/{id}/devices` | Device ids, signature keys and certificates of a user |
| `GET /v1/friends` | Friends and pending requests |
| `POST /v1/friends/requests` | Send a request (by handle) |
| `POST /v1/friends/requests/{user_id}/accept`, `DELETE /v1/friends/requests/{user_id}` | Accept, decline or cancel |
| `DELETE /v1/friends/{user_id}` | Remove a friend |
| `PUT /v1/blocks/{user_id}`, `DELETE /v1/blocks/{user_id}` | Block, unblock |
| `POST /v1/conversations` | Create a DM with a friend; returns the conversation id, or the existing one |
| `GET /v1/conversations` | Conversations of the user with their current epoch and last sequence number |

Creating a DM reserves a conversation id on the server. The creating device then builds the MLS group locally (group id = conversation id, `external_senders` = the server's key), adds its own other devices and the peer's devices, and submits the first commit with its Welcome.

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

message ConversationCreated {
  bytes conversation_id = 1;
  ConversationKind kind = 2;
  repeated bytes member_user_ids = 3;
}

// A friend enrolled or revoked a device. Clients show a notice in shared
// conversations when a device was added.
message UserDevicesChanged {
  bytes user_id = 1;
  bytes device_id = 2;
  bool added = 3;
}

// The device should upload more KeyPackages.
message KeyPackagesLow { uint32 remaining = 1; }
```

Delivery rules:

- Each conversation has one sequence, shared by application messages, proposals and commits. A device processes it in order.
- The server checks, for every message: the device is a current leaf of the group, the device is not blocked for delivery, the conversation-specific authorisation holds, and sizes are within limits.
- Application messages must be encrypted for the current epoch (`STALE_EPOCH` otherwise) and are refused while removals are pending (`REMOVAL_PENDING`). Both are recovered by the client without user-visible error: it applies or commits what is pending, re-encrypts for the new epoch and resends with the same `client_message_id`. Only repeated failure (three attempts) surfaces as "not sent, retry".
- A commit is validated against the public group state: valid signature, proposals allowed for the sender, new leaves carry valid device certificates. The epoch update is atomic.
- External proposals issued by the server are always `Remove`. Clients reject any other type from an external sender.
- `SendMessage` is idempotent on (`device`, `client_message_id`): a retry returns the original acknowledgement.
- The server deletes a stored message once every recipient device has acknowledged it, or after the retention limit (default 30 days), whichever comes first. A welcome is deleted when acknowledged.

### 5.3 Gateway: presence, typing, friends

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

message FriendshipChanged {
  bytes user_id = 1;
  FriendshipState state = 2;  // NONE | REQUEST_SENT | REQUEST_RECEIVED | FRIENDS
}
```

A blocked user receives no presence or typing events from the blocker, and their friend requests are dropped silently.

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

A message id is the pair (conversation id, sequence number); the sender learns it from `SendMessageAck`. The plaintext is padded to a multiple of 256 bytes before encryption.

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
  EPOCH_CONFLICT = 40;        // another commit won this epoch
  STALE_EPOCH = 41;           // message encrypted for a past epoch
  REMOVAL_PENDING = 42;       // commit the pending Remove proposals first
  INVALID_COMMIT = 43;        // failed validation against the public group state
  INVALID_KEY_PACKAGE = 44;
  NOT_A_MEMBER = 45;
  GROUP_INFO_REQUIRED = 46;
  NO_KEY_PACKAGE = 47;        // target device has none, not even last-resort

  // Social (M2)
  BLOCKED = 60;
  NOT_FRIENDS = 61;
}
```

REST errors use the same codes in a JSON body `{ "code": "EPOCH_CONFLICT", "message": "..." }` with the matching HTTP status (400, 401, 403, 404, 409, 413, 429, 500, 503).

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
| 4007 | Rate limit exceeded repeatedly |
| 4008 | Malformed frame |

## 7. Limits

Defaults; those marked * are configurable per instance and announced in `Ready.limits`.

| Item | Limit |
|---|---|
| Gateway frame | 1 MiB * |
| MLS application message (ciphertext) | 64 KiB * |
| Text of one message (plaintext) | 4 000 characters, enforced by clients |
| MLS commit | 256 KiB |
| MLS Welcome | 512 KiB |
| MLS GroupInfo | 512 KiB |
| KeyPackage | 4 KiB each, 100 per upload, 200 stored per device |
| REST JSON body | 64 KiB (512 KiB for KeyPackage upload) |
| Attachment (M5) | 500 MB * |
| Handle | 2–32 characters, `a–z 0–9 _ .`, lower case, unique |
| Display name | 1–64 characters |
| Devices per account | 10 |
| `Hello` deadline | 10 s |
| Heartbeat interval / timeout | 30 s / 75 s * |
| OPAQUE registration and login state | 60 s |
| Enrolment token | 5 min |
| `FetchMessages` page | 200 messages |
| Gateway requests per device | 30 per 10 s sustained, burst 60 |
| Typing updates | 1 per 3 s per conversation |
| Auth routes | 10 per minute per IP, 5 per minute per handle |
| Stored message retention | until acknowledged by all recipient devices, at most 30 days * |
| Password (client-enforced) | at least 12 characters, strength score ≥ 3 of 4 |

Exceeding a size limit yields `PAYLOAD_TOO_LARGE`; exceeding a rate yields `RATE_LIMITED` with `retry_after_ms`. A connection that keeps exceeding rates is closed with 4007.

## 8. Security requirements on implementations

- Decoders treat every input as hostile: bounded allocation, no recursion on attacker-controlled depth, strict length checks before copying.
- Neither side logs tokens, keys, `mls_*` fields or decrypted content.
- The client verifies `mls_external_sender_key` from `Ready` against the `external_senders` extension of each group and repairs mismatches as described in [ADR 0002](adr/0002-mls-via-openmls.md#external-sender-key-lifecycle).
- The gateway decoders are fuzz targets (`cargo-fuzz`); encode/decode round trips are property tested.
