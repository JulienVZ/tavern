# ADR 0016 — Security notices, stored and acknowledged per device

- Status: accepted
- Date: 2026-11-15

## Context

At M1 the server told a user's devices about security-relevant changes with gateway events only, and events reach connected devices only. A review of every place that notified devices showed:

| Event | Before |
|---|---|
| TOTP disabled by an administrator | Connected devices only. A device that was offline never learned about it. |
| Password changed | The other connected devices were signed out with a reason. A device that was offline found its session invalid, with no reason given, and nothing after signing in again. |
| Account recovered with the recovery key | Same as a password change. |
| Device revoked | The other connected devices received `DeviceListChanged`. Offline devices were not told. |
| Recovery key replaced | No device was told at all. |
| Instance restored from a backup (added 2026-11-24, ADR 0019 section 15) | Did not exist: every session is revoked, and what the user changed after the backup is undone. |
| Device enrolled | Already replayed at connection (`Ready.new_devices`). Not concerned. |

These are the events a user needs to see to notice that someone else is acting on their account. An attacker who chooses the moment can act while the victim's devices are off.

## Decision

A generic mechanism: **security notices**, stored per account and acknowledged per device.

- Table `security_notices`: account, kind (an enumeration stored as a small integer), date. **No free text**, no device identifier, no address. Table `security_notice_acks`: which device dismissed which notice.
- Kinds: TOTP disabled by an administrator (1), password changed (2), account recovered (3), device revoked (4), recovery key replaced (5), instance restored from a backup (6, since gateway minor 7), the same restore told to an administrator (7, since gateway minor 7). Numbers are shared by the database and the protocol and are never reused.
- Kind 6 carries one date more, the backup's (`security_notices.backup_taken_at`, `SecurityNotice.backup_taken_at_ms`; empty if the server does not know it), and still no text. The client explains it: whatever was done after that date is undone and messages sent since may be missing; the user is asked to do again what they changed since, first a password change and a new recovery key, then to check their devices (revoking again those revoked since), the people they block or unfriended, and their two-factor authentication. Recorded for every account by the server at start-up, in the transaction that handles the restore (ADR 0019, section 15). Kind 7 (added after the review of task 9b) carries the same date, and is recorded for every administrator of the restored database: the restore also undid what administrators did after the backup (accounts disabled since are active again, roles and TOTP disabled by an administrator as they were), which they must do again, and the same transaction revoked every invitation still valid.
- Delivery: pushed as a `SecurityNotice` event to connected devices, and listed in `Ready.security_notices` at every connection until the device sends `AckSecurityNotices`. The server subscribes the connection before reading the list, so a notice recorded in between arrives twice rather than not at all; clients identify notices by id.
- The device that performed the action does not need to be told: the notice is acknowledged for it when recorded. Actions without an acting device of the account (an administrator's action, a recovery) are shown everywhere.
- A device is told only about what happened after it was enrolled, **except for TOTP disabled by an administrator, for an account recovery and for a restore (kinds 6 and 7)** (added 2026-11-24: every device is signed out, and a device enrolled after the backup is unknown to the restored database, so it is enrolled anew, after the notice): these notices are also shown to devices enrolled later, as long as no device of the account has acknowledged them. No device of the account is known to have done either, and the user meets their effect anywhere: without this, a user who was signed out everywhere and signs in from a newly enrolled computer finds that no code is asked any more, with no explanation (found in manual testing on 2026-11-15); and after a recovery the legitimate user may well come back on a new computer. Devices that existed at the time still acknowledge each for itself. The three other kinds keep the plain rule: the device that acted acknowledges at once, so the extension would never show anything.
- Accepted limit: for these two kinds, whoever holds a session of the account can acknowledge the notice and thereby hide it from devices enrolled afterwards. Devices that existed when it happened still show it. See the threat model, residual risks.
- When TOTP is enabled again, the notices about an administrator disabling it are deleted: what they report no longer holds.
- Password change and recovery sign devices out; their notices are stored and not pushed, and are read after the next sign-in.
- The interface shows each notice until the user dismisses it on that device. A kind unknown to an older client is shown as a generic notice.
- Retention: 90 days. Older notices are not listed, and are deleted when the next notice is recorded for the account. No background job.
- Where the action already runs in a transaction (device revocation), the notice is inserted in the same transaction. Elsewhere it is recorded immediately after the action.
- Gateway minor version 1: `Ready.security_notices`, `SecurityNotice.notice_id` and `created_at_ms`, `AckSecurityNotices`.

Enrolments keep their own mechanism (`new_devices`, `AckDeviceList`): they carry the device to revoke and have a dedicated screen.

## Alternatives considered

- **One column per event** on `users` and `devices` (for example `totp_disabled_by_admin_at`): one migration per event and no history. Rejected by the maintainer in favour of a generic table.
- **Reuse `admin_audit_log`**: it describes what administrators did to the instance; most of these events are done by the user. Different audience and retention.
- **Notices inside MLS** (encrypted to the user's own devices): hides the events from the server, but the server performs every one of them and therefore knows them already. Would also need a self-group, which does not exist before M2.
- **Acknowledge once per account**: a notice dismissed by an attacker's session would vanish from the victim's devices. Per-device acknowledgement avoids this.

## Consequences

- The server stores, for up to 90 days, that these events happened and which devices dismissed them. This is metadata it already produced; it is listed in the threat model.
- A notice is information, not proof: a compromised server can withhold notices, as it can withhold any event. Notices protect against someone who obtained credentials, not against the instance.
- Where the notice is recorded after the action rather than in its transaction, a failure between the two returns an error to the client although the action took effect. Moving these actions into transactions is possible later without changing the protocol.
- Later events (for example the identity key of a contact changing, at M2) are not account notices and are handled in conversations.
