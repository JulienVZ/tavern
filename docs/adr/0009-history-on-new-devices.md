# ADR 0009 — Message history on a new device

- Status: proposed, scheduled after M5 (milestone M5b)
- Date: 2026-11-13

## Context

[ADR 0006](0006-no-prior-history-v1.md) accepts that a new device starts with an empty history. For an application used like Discord this is a major gap: people expect to install the client on a second computer and find their conversations. It is acceptable for the first releases only if the UI explains it and a remedy is planned.

Two properties must be kept: the server never holds a key that decrypts history, and a removed member gains nothing.

This ADR covers a user's **own** new device. Sharing a channel's past with a new *member* is a different question (policy, consent of the other members) and stays out of scope.

## Options

### A. Device-to-device transfer

An existing device of the user exports its local history to the new one.

- The two devices are already in an MLS group together (every conversation of the user), and they authenticate each other through certificates signed by the same account identity key.
- The old device builds an export (messages, attachment keys, conversation metadata), encrypts it with a fresh random key, uploads it as an ordinary encrypted blob in chunks, and sends the key to the new device in an MLS application message of a group that contains only the user's devices.
- The new device downloads, decrypts and imports. The blob is deleted afterwards.

| | |
|---|---|
| Server exposure | A temporary encrypted blob; no long-lived key anywhere |
| Works when | At least one other device of the user is online at some point |
| Fails when | The user has lost every device |
| Forward secrecy | Preserved against the server; the history exists only where it already existed |
| Cost | Export/import format, progress UI, large transfers (attachments are referenced, not copied, while their blobs still exist) |

### B. Encrypted backup under the recovery key

Each device continuously uploads an encrypted copy of what it receives; a new device restores it with the recovery key.

- A backup key is derived from the recovery key. Devices that hold it encrypt each message (or batches) and upload them to the server as opaque records.
- A new device asks for the recovery key, derives the backup key and downloads everything.

| | |
|---|---|
| Server exposure | The full history as long-lived ciphertext, under one long-lived key |
| Works when | Always, including after losing every device, provided the user kept the recovery key |
| Fails when | The recovery key is lost |
| Forward secrecy | Weakened: whoever obtains the recovery key and the server's data reads all backed-up history |
| Cost | Server storage grows without bound unless capped; devices must keep the backup key, so a stolen device exposes the backup; the recovery key, shown once today, would have to be typed again on each new device |

### C. Both

Transfer (A) by default when another device is available; backup (B) as an opt-in for users who want to survive the loss of all devices.

## Proposed decision

Implement **A first**, at milestone M5b, once attachments exist (the export travels as an encrypted blob). Consider **B as an opt-in**, per user, with an instance-level switch and quota, in a later milestone.

Reasons: A adds no long-lived secret and no long-lived ciphertext, and covers the common case (a second computer). B changes the security posture of the recovery key and of the server's storage, and should be a choice the user makes knowingly.

## What v1 does meanwhile

- When a device is enrolled, and when a conversation is opened on it for the first time, the UI says that earlier messages stay on the user's other devices and are not available here.
- The top of each conversation shows a marker "messages before this point are not available on this device" at the point where the device joined, instead of an empty space.
- The instance's retention period for undelivered ciphertext stays configurable (30 days by default), so a device that was offline for a while still catches up.

## Consequences

- The local store schema needs stable message identifiers and an export format from M2 on, so that an import can merge without duplicates.
- A set of "own devices" MLS group per user becomes necessary (it is also what [ADR 0008](0008-encrypted-profiles.md) uses to synchronise the profile key).
- Until M5b, losing or replacing a device loses access to its history.
