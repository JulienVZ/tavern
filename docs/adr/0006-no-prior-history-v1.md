# ADR 0006 — No prior history for new members in v1

- Status: accepted
- Date: 2026-11-13

## Context

MLS gives forward secrecy and post-compromise security by deriving new secrets at each epoch. A leaf that joins at epoch *n* cannot derive the secrets of earlier epochs, so it cannot decrypt messages sent before it joined. This holds for a new member of a channel, and equally for a **new device of an existing member**.

Users coming from mainstream chat applications expect to scroll back through a channel after joining and to see their history on a new computer.

## Decision

In v1:

- A new member of a DM, group or channel sees messages from the moment their device joins the MLS group, and nothing earlier.
- A new device of an existing user starts with an empty history for every conversation.
- History lives in each device's local encrypted store. The server keeps ciphertext only for delivery (until every recipient device has acknowledged it, with a configurable maximum, 30 days by default — this retention rule awaits maintainer validation).
- The UI states this plainly where it matters: when joining a channel, when adding a device, and in the documentation.

## Alternatives considered

- **Server-side history readable by new members**: requires the server to hold keys or plaintext. Excluded.
- **History sharing by an existing member**: a member device re-encrypts past messages (or the past epoch secrets) for the newcomer. Workable, but it needs a policy (who may share, how far back), a transport for large exports, and care not to defeat forward secrecy silently. Deferred, to be designed in its own ADR.
- **Device-to-device history transfer** for a user's own new device: same mechanism restricted to one user; the most likely first step after v1.
- **Encrypted server-side backup under a user-held key**: restores history after device loss, at the cost of keeping long-lived ciphertext and a long-lived key. Also deferred.

## Consequences

- Removed members and stolen devices cannot be used to recover messages the device never received, and new members cannot read what was said before they arrived. For a group of friends this is sometimes a drawback and must be explained.
- Losing every device means losing the message history, even though the recovery key restores the identity.
- Local search covers only what the device has received.
- The server's storage needs stay small and bounded.
- The door stays open: the content format and the blob storage are designed so that a history export can later be sent as an encrypted attachment.
