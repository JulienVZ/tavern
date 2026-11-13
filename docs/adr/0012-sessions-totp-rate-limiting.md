# ADR 0012 — Sessions, TOTP, rate limiting and administration of accounts

- Status: accepted
- Date: 2026-11-14

## Context

[ADR 0003](0003-opaque-authentication.md) covers how a password is proved. This ADR records what surrounds it on the server at milestone M1: what a successful login yields, how sessions live and die, how TOTP is checked, how abuse is limited, and what an administrator can do to an account. It also records the dependencies added for these (`totp-rs`, `governor`, `utoipa`).

## Decision

### From login to session

1. A successful OPAQUE login (and TOTP step, when enabled) yields a **grant**: an enrolment token and a session nonce, both single use and valid for five minutes, plus the wrapped account key. The wrapped key is never returned before the TOTP step has passed.
2. With the enrolment token the client either **enrols a new device** (`POST /v1/devices`, with a certificate signed by the account identity key that names this account) or **reopens the session of an existing device** (`POST /v1/devices/{id}/session`, with the device key's signature over the session nonce, the account id and the device id). A revoked device, an unknown device and a device of another account get the same refusal.
3. Either way the result is a **session token**: 32 random bytes, stored as a SHA-256 hash, one per device, sliding expiry (90 days unused by default, `TAVERN_SESSION_TTL_DAYS`).

A session ends when the user logs out, when the device is revoked, when the account is disabled, when the password is changed or recovered (other devices), or when it expires.

Enrolling a device notifies every other connected device of the account. A device that was offline learns about it at its next connection (`devices.devices_seen_at`).

At most ten active devices per account.

### State between requests

OPAQUE login state, pending TOTP steps, enrolment tokens and challenges are kept **in memory**, in maps whose entries expire (60 seconds for an OPAQUE exchange, five minutes otherwise), are single use and are capped at 10 000 per kind. When a cap is reached the server answers `UNAVAILABLE` instead of growing. A restart drops them; clients start the exchange again. This assumes a single server process, which is the deployment model.

### TOTP

- RFC 6238, SHA-1, six digits, 30-second steps, one step of drift tolerated either way (`totp-rs` 6, MIT).
- The shared secret is stored encrypted with XChaCha20-Poly1305 under the instance's TOTP key, bound to the account id.
- The last accepted time step is stored, and a code is accepted only for a newer step: a code cannot be used twice.
- Ten recovery codes (128 random bits each) are issued when TOTP is confirmed, stored as hashes, single use.
- Five wrong codes close a login; it must be restarted from the password.
- TOTP is enforced by the server. It protects a stolen password from being used over the network. It does not protect the wrapped account key from someone who controls the server; the threat model says so.
- **An administrator can disable a user's TOTP** (`POST /v1/admin/users/{id}/totp/disable`) for a user who lost both the authenticator and the recovery codes. Because TOTP is a server-side check, this gives the administrator nothing they could not already obtain by other means. The user's devices are notified and the action is recorded.

### Rate limiting

In-memory token buckets (`governor` 0.10, MIT):

- 30 requests per minute per client address on `/v1/auth/*`;
- 5 attempts per minute per handle on login, registration and recovery starts, counted whether or not the account exists.

The client address is the TCP peer, or, when `TAVERN_TRUST_FORWARDED_FOR` is set, the **last** entry of `X-Forwarded-For`: the one appended by the reverse proxy. Earlier entries come from the client and are never used. The reference compose file sets the variable and publishes no port for the server, so Caddy is the only peer; CI checks both. Addresses are held in memory only and are never logged or stored.

### Administration

- The first administrator registers with an invitation created on the host (`tavern-server create-admin-invite`, wrapped by `deploy/scripts/create-admin.sh`): single use, valid 24 hours.
- Administrators create and revoke invitations, list accounts, disable and re-enable accounts, and disable a user's TOTP. They cannot target their own account with the last three.
- Actions on invitations and on other accounts are recorded in `admin_audit_log`: actor, action code, target, time. No free text.
- Invitation codes are 128 random bits, shown once, stored as hashes.

### OpenAPI

The REST API is described with `utoipa` 6 and served at `GET /v1/openapi.json`. The request and response types live in the `protocol` crate and derive their schemas behind a feature that only the server enables.

## Alternatives considered

- **JWT or other self-contained session tokens**: no database lookup per request, but revocation needs a deny list, which brings the lookup back.
- **Persisting exchange state in PostgreSQL**: survives restarts and allows several server processes; neither is needed at this scale, and it would put short-lived secrets on disk.
- **`tower_governor`**: ready-made middleware, but it keys on the peer address or on the first forwarded entry, and cannot key on a handle read from the body.
- **Letting only the user disable TOTP**: a user who lost everything would be locked out for good, or would have to use the recovery key, which deliberately does not disable TOTP.
- **Storing TOTP secrets in clear**: a database dump would reveal them.

## Consequences

- A server restart interrupts logins in progress, nothing more.
- Rate limits reset on restart and are per process.
- Behind another proxy than the reference Caddy, the administrator must make sure it appends the client address and that the server is not reachable directly; otherwise `TAVERN_TRUST_FORWARDED_FOR` must stay unset and all clients share the proxy's bucket.
- Losing the TOTP key makes stored secrets unreadable: affected users need their TOTP disabled by an administrator and set up again.
