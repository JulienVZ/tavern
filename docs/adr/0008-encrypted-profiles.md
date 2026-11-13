# ADR 0008 — Encrypted profiles with a profile key (future work)

- Status: proposed, not scheduled for v1
- Date: 2026-11-13

## Context

In v1 the server can read each user's profile: display name, avatar, banner, bio and custom status. This was decided to keep M1–M5 simple, and it is listed in the threat model. Handles, and the names of servers, channels and roles, are also visible; they are needed for invitations and permissions and are outside the scope of this ADR.

Profiles are personal data that the server has no functional need to read. Signal solved the same problem with a per-user profile key.

## Decision (proposed)

After v1, encrypt profiles on the client:

- Each account has a random 256-bit **profile key**, stored in the user's own devices and synchronised between them through an MLS group containing only that user's devices.
- Profile fields and profile images are encrypted with keys derived from the profile key and uploaded as opaque blobs. The server stores ciphertext and a version number.
- The profile key is shared inside MLS application messages: to a friend when the friendship is accepted, and to the members of a group or channel on first participation. A client that holds a user's profile key fetches and decrypts their profile; one that does not shows the handle only.
- Blocking a user or leaving every shared conversation triggers a profile key rotation and re-encryption, so the other party cannot read later versions.
- The handle stays visible to the server and remains the fallback display.

## Alternatives considered

- **Keep profiles visible** (v1 behaviour): simplest; the admin can read names and see avatars.
- **Send the profile itself inside each conversation**: no profile key, but every change must be pushed to every conversation and large images are duplicated.
- **Anonymous credentials for profile fetches** (as Signal does, to hide who fetches whose profile): the server already knows the social graph here, so this adds complexity without much benefit.

## Consequences

- The server would no longer see display names, bios, statuses or avatars.
- A user who has no shared context with another sees only a handle; search and invitations work on handles.
- Rotation on block has a cost proportional to the number of contacts.
- The v1 schema keeps profile fields in separate columns and profile images as ordinary blobs, so the migration replaces their content with ciphertext without restructuring.
- Member nicknames inside a server could follow the same approach, keyed per server.
