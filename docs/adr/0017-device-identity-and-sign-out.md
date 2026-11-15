# ADR 0017 — Device identity, sign-out and the key of the local store

- Status: proposed
- Date: 2026-11-15

## Context

From M2 the message history lives on the device, in an encrypted local store, together with the MLS state of every conversation. Losing the identity of a device now means losing its history.

What M1 does ([ADR 0014](0014-client-secret-storage-m1.md)):

- The keychain holds **one record per instance and profile**: account id, handle, device id, device key seed, session token.
- **Signing out** revokes the session on the server and removes the session token from the record. The device key is kept: signing in again to the same account reopens the same device.
- **Signing in to another account** in the same profile ignores the record (it belongs to another account), enrols a new device and overwrites the record. The first account's device identity is lost; its next sign-in enrols yet another device. Repeated, this fills the limit of ten devices.
- A device that learns it was revoked deletes its record.

Requirements set by the maintainer:

1. Signing out and back in to the same account, on the same computer, finds the same device and its local history.
2. One profile keeps the device identity of several accounts: one per instance and per account.
3. A separate, explicit action "sign out and erase this device" deletes keys and local data and revokes the device.
4. The local store of a signed-out account stays encrypted and unreadable without a new authentication.
5. The server must not be able to contribute, alone, to reading content: a malicious host who gets hold of a signed-out user's computer must not be able to read the history.

## Decision

### Records

- **One keychain record per instance, profile and account**, named `<instance>#<profile>@<user id>`. It holds the account id, the handle, the device id, the device key seed, the wrapped store key (below) and, while signed in, the session token and the store key.
- **One index record per instance and profile**, `<instance>#<profile>`: the accounts known on this computer (id and handle) and the last one used, to prefill the sign-in screen and to resume at start-up.
- The M1 record is converted at first read.
- After OPAQUE completes, the login grant names the account; the client loads that account's record and reopens its device, or enrols a new one if there is none.
- The local store of an account is a directory of its own, named after the instance, the profile and the account.

### Sign-out and erasure

| Action | Server | Keychain | Local store |
|---|---|---|---|
| **Sign out** | Session revoked. The device stays enrolled and stays a member of its conversations. | Session token and store key removed. Device key seed and wrapped store key kept. | Kept, encrypted. |
| **Session ended by the instance** (password changed elsewhere, expiry, account disabled) | — | Same as signing out, as soon as the device learns it. | Kept, encrypted. |
| **Sign out and erase this device** (confirmation dialog) | Device revoked; the server removes it from its MLS groups. | Record deleted, account removed from the index. | Deleted. |
| **Revoked from another device** | Device revoked. | Record deleted when the device learns it. | Deleted when the device learns it. |

A signed-out device still receives nothing but stays a group member; its messages wait on the server within the retention limit. Devices that stay away longer are removed from their groups (delay and return path are specified in the MLS plan of M2).

### The key of the local store

The store is encrypted with a random 256-bit **store key**, generated on the device when the store is created. The question is what protects that key while the account is signed out. Three options were evaluated.

**(a) A wrapping key held by the server only.** The server keeps a random secret per device and returns it when that device opens a session.

**(b) A key derived from a secret the server never has**, which survives a password change: the private account identity key (AIK), through HKDF with a dedicated label and the device id.

**(c) Both combined**: the wrapping key needs the AIK *and* the server's secret.

| | (a) server only | (b) AIK only | (c) both |
|---|---|---|---|
| Thief with the signed-out computer, no password | protected | protected | protected |
| Malicious host with the signed-out computer | **reads the history** | protected up to the password (see below) | protected up to the password |
| Someone with the password and the computer, after the user revoked the device | protected (secret deleted) | **reads the history** | protected (secret deleted) |
| After a password change on another device | works | works | works |
| After a recovery with the recovery key | works | works | works |
| Offline start of a device that stayed signed in | works | works | works |
| Server loses its secret for the device | signed-out store lost | no effect | signed-out store lost |

Option (a) breaks requirement 5 and is rejected. **Option (c) is adopted**: it is the only one that covers both the malicious host and the stolen computer whose owner revoked it. Its cost against (b) is the last row.

Construction (HKDF-SHA-256 and XChaCha20-Poly1305 from RustCrypto, both already used by the `crypto` crate; nothing is implemented by hand):

```
account_part = HKDF(ikm = AIK private seed,
                    info = "tavern/v1/local-store/account" || user id || device id)
server_part  = 32 random bytes, generated by the server at enrolment, one per device
wrapping_key = HKDF(ikm = account_part || server_part,
                    info = "tavern/v1/local-store/wrap" || device id)
wrapped      = XChaCha20-Poly1305(wrapping_key, store key, aad = version || user id || device id)
```

- `wrapped` is kept in the keychain record. `account_part`, `server_part` and `wrapping_key` are never stored on the device; they are erased from memory once the store key is unwrapped.
- **While signed in**, the store key itself is in the keychain record, next to the session token. Start-up needs neither the password nor the network.
- **At sign-in**, the client already receives the AIK wrapped under the OPAQUE export key (`LoginGrant.wrapped_password_copy`); it unwraps it, derives `account_part`, erases the AIK, and receives `server_part` in the response that opens the device's session.
- **Server side**: a new column `devices.local_store_share`, returned only by the two routes that open a session for that very device, deleted when the device is revoked. A device enrolled before this change gets one at its next session.

### Checks asked for

- **Password change.** The AIK does not change; only its wrapped copy does. On the device that changes the password nothing moves (the store key is in the keychain). Other devices are signed out; at their next sign-in the new export key unwraps the same AIK, hence the same `account_part`. Works.
- **Recovery with the recovery key.** The recovery sets a new password and re-wraps the same AIK. Same as above. Works.
- **Offline start, device still signed in.** The store key is in the keychain. Works. If the session was ended meanwhile, the store stays readable until the device reaches the instance and learns it; the store key is then removed.
- **Offline, signed out.** Not possible, as today: signing in needs the instance.
- **The server loses its part.** `local_store_share` is a column of the database, so it is in every `backup.sh` archive (the PostgreSQL dump). It is never rotated, so a device enrolled before the backup keeps the same part after a restore. A device **enrolled after** the restored backup is unknown to the server: if it was signed in, the server ends its session and it must be enrolled again as a new device; its local history can no longer be opened. This is a small part of a larger problem: restoring an old database also rewinds the public state of every MLS group, which the restore procedure must already treat as an incident. The self-hosting guide will say that a restore loses the local history of devices enrolled since the backup, and recommend frequent backups.

## Limits to accept

1. **"Protected up to the password".** A malicious host holds the OPAQUE record and the wrapped AIK. With the seized computer it can guess passwords offline, at Argon2id cost; a guessed password yields the AIK and therefore the store. This is residual risk 8 of the threat model, which already exists; (b) and (c) add no new way in, but they do not remove this one. The password strength rule is what holds.
2. **A signed-in computer is not protected by any of this**: its store key is in the keychain, like its session token (residual risk 14). Revoking it protects the store only if the device was signed out, or once it learns of the revocation and deletes its data.
3. **The AIK is in memory at every password sign-in**, for the time of one derivation. Today it is unwrapped only at enrolment and for credential changes.
4. **The AIK seed is used as HKDF input** in addition to signing. The label separates the two uses, and Ed25519 itself only uses the seed through SHA-512. The alternative, a separate account secret wrapped next to the AIK, needs two more wrapped copies and their update at every password change and recovery; it is kept in reserve should the AIK ever need to be rotated.
5. **Availability.** With (c), losing the server's row loses the signed-out store, which (b) alone would not. This is the price of making a revocation final.

## Alternatives considered

- **Store key derived from the OPAQUE export key** (the password): a password change made on another device would make every other device's store unreadable.
- **Store key kept in the keychain after sign-out**: a signed-out account would be readable by anyone with the unlocked computer; contradicts requirement 4.
- **`server_part` derived from an instance secret instead of stored per device**: survives the loss of a row, but can no longer be destroyed at revocation.
- **Storing `server_part` encrypted under a new instance key**: one more secret whose loss would lock every signed-out store, for no gain, since the part is useless without the AIK and the device. Proposed instead: a new column class in `docs/database-schema.md` for "server half of a client key, useless alone".

## Consequences

- REST: the session-opening responses gain `local_store_share`; `REST_MINOR_VERSION` is incremented because clients rely on it.
- Schema: `devices.local_store_share`, with its class documented; the threat model lists it under what the server holds.
- `client-core`: the secret store handles several records and an index; `logout` and a new `erase_device` are distinct; the M1 record is migrated.
- UI: the sign-in screen offers the accounts known on this computer; "sign out and erase this device" sits in the device settings behind a confirmation that says the local history will be deleted.
- Tests: sign out and back in keeps the device and opens the store; two accounts alternate in one profile without enrolling new devices; the wrapped key does not open with a wrong AIK, a wrong server part or another device id; after erasure the device is revoked and nothing is left; after a password change and after a recovery, a signed-out device opens its store again.
- [ADR 0014](0014-client-secret-storage-m1.md) is superseded for the layout of the keychain record.
