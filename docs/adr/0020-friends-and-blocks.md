# ADR 0020 — Friends and blocks

- Status: accepted (2026-11-18)
- Date: 2026-11-18

## Context

M2 gives each user a friend list. Friendship gates who may claim a user's KeyPackages ([ADR 0019](0019-mls-direct-messages.md), section 3) and create a DM with them (section 4); section 16 of that ADR says what unfriending and blocking do to a DM that exists. [`protocol.md`](../protocol.md#51-rest) lists the routes and the `FriendshipChanged` event, and says that the requests of a blocked user are dropped silently. The server already sees the friend graph, the pending requests and the blocks ([threat model](../threat-model.md), section 4).

Left to decide before task 6 of M2: what a request to an unknown handle answers, how a block stays undisclosed, what crossed requests do, how often requests may be sent, and which events tell the devices.

## Decision

1. **One row per pair of users**, smaller id first (`friendships`): a request or a friendship, so **at most one pending request per pair**. Sending a request again changes nothing.
2. **Requests by handle.** An unknown handle answers `NOT_FOUND`: handles are visible metadata in v1 (`CLAUDE.md` section 5), and only enumeration from outside an account is prevented, by the login decoys ([ADR 0003](0003-opaque-authentication.md)). A user sends **at most 20 requests an hour**, unknown handles included (`TAVERN_FRIEND_REQUESTS_PER_HOUR`), counted exactly over any hour, in memory: the count starts from zero when the server restarts. A request to oneself is refused.
3. **Crossed requests make friends**: a request to a user who has already sent one to the sender accepts theirs.
4. The recipient accepts or declines a request; its sender may cancel it; either friend may end the friendship.
5. **Blocking** ends the friendship or the request between the two users, in the same transaction. The blocker cannot send a request to the blocked user (`BLOCKED`) before unblocking them. Blocking again changes nothing.
6. **A block is never disclosed** to the blocked user. They see what an unfriending or a declined request shows: no event names the block, and their friend list no longer shows the blocker. A request they send to the blocker gets the answer any request gets, and stays in their own list of sent requests, pending; the blocker never sees it, and is told nothing of it (`friendships.hidden`). **When the block is lifted, that request is deleted** (decided 2026-11-18): unblocking makes the user reachable again, it accepts nothing that was sent during the block.
7. **Events.** `FriendshipChanged` (user, state) goes to the connected devices of both users, each with their own view of the relation: `REQUEST_SENT` to the sender, `REQUEST_RECEIVED` to the recipient, `FRIENDS`, `NONE`, and `BLOCKED` to the blocker's devices only. A device that is not connected reads `GET /v1/friends` when it connects. `UserDevicesChanged` tells the connected devices of a user's friends when that user enrols or revokes a device ([ADR 0003](0003-opaque-authentication.md)).
8. Each user in the friend list comes with their account identity key, which the client pins when the friendship is accepted (ADR 0019, section 10; task 11 of M2).
9. A friend's KeyPackages are claimable, within the limits per pair of ADR 0019, section 3.
10. Operations on one pair take turns on an advisory lock held until their transaction ends (the row may not exist yet): two crossed requests, an acceptance and a block never interleave.

## Alternatives considered

- **The same answer for an unknown handle as for a real one**: the server would have to show its sender a pending request to an account that does not exist, and keep it consistent forever. Rejected: handles are not secret among the members of an instance.
- **Dropping a request to a blocker outright**: the request would vanish from its sender's list at once, or never appear, which would disclose the block.
- **Turning such a request into a normal one when the block is lifted**: rejected by the maintainer. Being reachable again is not accepting what was sent meanwhile.
- **Telling the blocked user**: rejected in ADR 0019, section 16, consistently with the silent dropping of `protocol.md`.

## Consequences

- The server stores a request the blocker never sees: metadata of the same kind as the friend list, visible to the server only.
- What unfriending and blocking do to an existing DM (read-only on both sides) is ADR 0019, section 16, enforced with the messages (tasks 8 and 9 of M2). The interface comes with task 12.
- REST 1.4 and gateway minor 3; a new error code, `BLOCKED`.

## Implementation (task 6 of M2)

- Migration 0007 (`friendships`, `blocks`, with checks: the sender is one of the pair, a hidden request is pending, an accepted friendship has its date); `crates/server/src/routes/friends.rs`; the claim of a friend's KeyPackages in `routes/key_packages.rs`; `UserDevicesChanged` at enrolment and revocation; `client-core`: the calls, and the two events. The desktop application leaves the two events aside until the interface of task 12.
- Tests on PostgreSQL: a request accepted, declined, cancelled; crossed requests; unknown, own and malformed handles; the block, its silent request, and its deletion at unblock; the limit per user; the schema's checks; the events of both users, nothing to the blocker, and devices told to friends only; a friend's KeyPackages within the limit per pair, forbidden to a pending request and after an unfriending. End to end: two users become friends through `client-core`, a block ends it.
