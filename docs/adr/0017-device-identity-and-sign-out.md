# ADR 0017 — Device identity, sign-out and the key of the local store

- Status: accepted (2026-11-16)
- Date: 2026-11-15
- Amends: [ADR 0011](0011-account-identity-and-primitives.md) (the wrapped copies now hold an account root secret), [ADR 0014](0014-client-secret-storage-m1.md) (layout of the keychain records)

## Context

From M2 the message history lives on the device, in an encrypted local store, together with the MLS state of every conversation. Losing the identity of a device now means losing its history.

What M1 did ([ADR 0014](0014-client-secret-storage-m1.md)):

- The keychain held **one record per instance and profile**: account id, handle, device id, device key seed, session token.
- **Signing out** revoked the session on the server and removed the session token from the record. The device key was kept: signing in again to the same account reopened the same device.
- **Signing in to another account** in the same profile ignored the record (it belonged to another account), enrolled a new device and overwrote the record. The first account's device identity was lost; its next sign-in enrolled yet another device. Repeated, this filled the limit of ten devices.
- A device that learnt it was revoked deleted its record.

Requirements set by the maintainer:

1. Signing out and back in to the same account, on the same computer, finds the same device and its local history.
2. One profile keeps the device identity of several accounts: one per instance and per account.
3. A separate, explicit action "sign out and erase this device" deletes keys and local data and revokes the device.
4. The local store of a signed-out account stays encrypted and unreadable without a new authentication.
5. The server must not be able to contribute, alone, to reading content: a malicious host who gets hold of a signed-out user's computer must not be able to read the history.

## Decision

### Records

- **One keychain record per instance, profile and account**, named `<instance>#<profile>@<user id>`. It holds the account id, the handle, the device id, the device key seed, the wrapped store key (below) and, while signed in, the session token and the store key.
- **One index record per instance and profile**, `<instance>#<profile>`: the accounts known on this computer (id and handle) and the last one used, to offer them on the sign-in screen and to resume at start-up.
- A record this version cannot read is treated as absent. The M1 record, stored under the key that now holds the index, is therefore ignored: the M1 test accounts are recreated rather than migrated (below).
- After OPAQUE completes, the login grant names the account; the client loads that account's record and reopens its device, or enrols a new one if there is none.
- The local store of an account (from task 2 of M2) is a directory of its own, named after the instance, the profile and the account.

### Sign-out and erasure

| Action | Server | Keychain | Local store |
|---|---|---|---|
| **Sign out** | Session revoked. The device stays enrolled and stays a member of its conversations. | Session token and store key removed. Device key seed and wrapped store key kept. | Kept, encrypted. |
| **Session ended by the instance** (password changed elsewhere, expiry, account disabled) | — | Same as signing out, as soon as the device learns it. | Kept, encrypted. |
| **Sign out and erase this device** (confirmation dialog) | Device revoked; its part of the store key is erased; from task 9 the server also removes it from its MLS groups. | Record deleted, account removed from the index. | Deleted. |
| **Revoked from another device** | Same as above. | Record deleted when the device learns it. | Deleted when the device learns it. |

Erasure revokes first: if the instance cannot be reached, nothing is deleted, the user stays signed in and sees the error, and can retry.

A signed-out device receives nothing but stays a group member; its messages wait on the server within the retention limit. Devices that stay away longer than a configurable delay (90 days by default) are removed from their groups by the server; the delay and the return path are specified in the MLS plan of M2.

### Account root secret

Until now the two wrapped copies stored by the server (under the password and under the recovery key) held the seed of the account identity key (AIK) itself. They now hold an **account root secret**: 32 random bytes generated at registration. Every long-term secret of the account is derived from it with HKDF-SHA512 and a label of its own:

| Derived secret | HKDF info |
|---|---|
| Seed of the AIK | `tavern account root v1 identity key` |
| Account part of a device's store key | `tavern account root v1 local store` `0x00` user id device id |
| Profile key ([ADR 0008](0008-encrypted-profiles.md)), history backup key ([ADR 0009](0009-history-on-new-devices.md)) | to be defined by those ADRs, with labels of their own |

- Each use has its own key: a signing key is not also a key-derivation input.
- No additional wrapped copy: the two existing copies cover every derived secret, and a password change or a recovery re-wraps one value.
- A future change of the AIK (a new derivation label, a new signature algorithm) does not change the account part of the store keys: the stores of signed-out devices stay readable.
- The root secret exists in clear only in client memory, during a sign-in or a credential change, in a type that is erased when dropped and prints as `<redacted>`.

The wrapped copy format moves to **version 2** (same layout, 73 bytes; new labels `tavern account root wrap v2 password` and `... recovery`, associated data `tavern account root wrapped v2`). Version 1 is no longer read: the accounts created before this change (test accounts only) must be recreated. The OPAQUE suite number is unchanged, since neither OPAQUE nor Argon2id changed.

### The key of the local store

The store is encrypted with a random 256-bit **store key**, generated on the device when the device is enrolled. The question is what protects that key while the account is signed out. Three options were evaluated.

**(a) A wrapping key held by the server only.** The server keeps a random secret per device and returns it when that device opens a session.

**(b) A key derived from a secret the server never has**, which survives a password change: the account root secret.

**(c) Both combined**: the wrapping key needs the account root secret *and* the server's secret.

| | (a) server only | (b) account only | (c) both |
|---|---|---|---|
| Thief with the signed-out computer, no password | protected | protected | protected |
| Malicious host with the signed-out computer | **reads the history** | protected up to the password (see limits) | protected up to the password |
| Someone with the password and the computer, after the user revoked the device | protected (secret erased) | **reads the history** | protected (secret erased) |
| After a password change on another device | works | works | works |
| After a recovery with the recovery key | works | works | works |
| Offline start of a device that stayed signed in | works | works | works |
| Server loses its secret for the device | signed-out store lost | no effect | signed-out store lost |

Option (a) breaks requirement 5 and is rejected. **Option (c) is adopted**: it is the only one that covers both the malicious host and the stolen computer whose owner revoked it. Its cost against (b) is the last row.

Construction (HKDF-SHA512 and XChaCha20-Poly1305 from RustCrypto, already used by the `crypto` crate; nothing is implemented by hand; code in `crates/crypto/src/local_store.rs`):

```
account_part = HKDF(root secret, info = "tavern account root v1 local store" || 0x00 || user id || device id)
server_part  = 32 random bytes, generated by the server with the device's first session
wrapping_key = HKDF(account_part || server_part, info = "tavern local store wrap v1" || 0x00 || device id)
wrapped      = 0x01 || nonce (24) || XChaCha20-Poly1305(wrapping_key, store key, aad = label || user id || device id)
```

- `wrapped` is kept in the keychain record. `account_part`, `server_part` and `wrapping_key` are never stored on the device; they are erased from memory once the store key is unwrapped.
- **While signed in**, the store key itself is in the keychain record, next to the session token. Start-up needs neither the password nor the network.
- **At sign-in**, the client receives the root secret wrapped under the OPAQUE export key (`LoginGrant.wrapped_password_copy`), opens it, derives the account part and erases the root secret. It receives the server part in the response that opens the device's session (`SessionResponse.local_store_share`, REST 1.2).
- **Server side**: column `devices.local_store_share`, of the new class `HALF` ("server half of a client key, useless alone", stored in clear, see [the schema](../database-schema.md)). It is returned only by the two routes that open a session for that very device, never changes once created, and is erased when the device is revoked.

### Checks asked for

- **Password change.** The root secret does not change; only its wrapped copy does. On the device that changes the password nothing moves (the store key is in the keychain). Other devices are signed out; at their next sign-in the new export key opens the same root secret, hence the same account part. Tested end to end.
- **Recovery with the recovery key.** The recovery sets a new password and re-wraps the same root secret. Same as above. Tested end to end.
- **Offline start, device still signed in.** The store key is in the keychain. If the session was ended meanwhile, the store stays readable until the device reaches the instance and learns it; the store key is then removed.
- **Offline, signed out.** Not possible, as before: signing in needs the instance.
- **The server loses its part.** `local_store_share` is a database column, so it is in every `backup.sh` archive (the PostgreSQL dump), and it never changes, so a device enrolled before the backup gets the same part after a restore. A device enrolled **after** the restored backup is unknown to the restored database: its session no longer exists and it must be enrolled again as a new device, without local history. A device whose row exists but whose part is missing signs in, receives a new part, cannot open its old store and says so ("the local data of this device could not be opened"); a new, empty store is created. Restoring an old database also rewinds the public state of every MLS group; that is handled in the MLS plan of M2. `docs/self-hosting.md` says that a restore loses the local history of devices enrolled since the backup.

### Session expiry and what the user sees

- A session expires after **90 days without use** (`TAVERN_SESSION_TTL_DAYS`, 1 to 3650). The expiry slides: each use moves it forward, at most once an hour. A device used at least once every 90 days never has to sign in again.
- The instance also ends sessions when the password is changed on another device (other devices only), when the account is recovered (all devices), when the device is revoked, and when an administrator disables the account.
- When a session ends, the device learns it at once if connected (gateway), otherwise at its next request. It then forgets the session token and the store key and shows the sign-in screen with the reason: "Your session expired. Sign in again.", "Your password was changed on another device. Sign in again.", "Your account was disabled by an administrator." or "This device was signed out." The handle is prefilled, the accounts known on this computer are offered, and a hint says that this computer is already a device of the account and that signing in finds it again with its local data.
- After signing in again, the same device continues: no new-device notice, and its local history is back. If the store could not be opened (lost server part), a notice says so.

## Limits to accept

1. **"Protected up to the password".** A malicious host holds the OPAQUE record and the wrapped root secret. With a seized signed-out computer it can guess passwords offline, at Argon2id cost; a guessed password yields the root secret and therefore the store. This is residual risk 8 of the threat model; options (b) and (c) add no new way in, but do not remove this one. The password strength rule is what holds.
2. **A signed-in computer is not protected by any of this**: its store key is in the keychain, like its session token (residual risk 14). Revoking it protects the store once the device is offline-signed-out or learns of the revocation and deletes its data.
3. **The root secret is in memory at every password sign-in**, for the time of a few derivations. Before, the AIK was unwrapped only at enrolment and for credential changes.
4. **Availability.** With (c), losing the server's row loses the signed-out store, which (b) alone would not. This is the price of making a revocation final.

## Alternatives considered

- **Account part derived directly from the AIK seed**: proposed in the first draft. Rejected by the maintainer: it uses a signing key as derivation input, and rotating the AIK one day would make every signed-out store unreadable. The root secret gives the same properties without these two defects and without an extra wrapped copy.
- **A separate account secret wrapped next to the AIK**: same separation, but two more wrapped copies to keep in step at every password change, recovery and recovery key rotation.
- **Store key derived from the OPAQUE export key** (the password): a password change made on another device would make every other device's store unreadable.
- **Store key kept in the keychain after sign-out**: anyone with the unlocked computer could read a signed-out account; contradicts requirement 4.
- **Server part derived from an instance secret instead of stored per device**: survives the loss of a row, but can no longer be destroyed at revocation.
- **Server part encrypted under a new instance key**: one more secret whose loss would lock every signed-out store, for no gain, since the part is useless without the root secret.

## Consequences

- `crypto`: `AccountRootSecret` (generation, wrapping, derivation of the AIK and of the account part) replaces the wrapping of the AIK; module `local_store` for the store key. Formats frozen by known-answer tests.
- REST 1.2: session-opening responses carry `local_store_share`; the wrapped copies hold the root secret.
- Schema: migration 0004, `devices.local_store_share` of class `HALF`.
- `client-core`: one record per account plus an index; `logout` keeps the device, `erase_device` revokes and forgets it; `Client::local_store_key` gives the key the local store of task 2 will use; `SignedIn::store_reset` reports a store that could not be opened.
- Desktop: accounts known on this computer on the sign-in screen; "Sign out and erase this device" on the current device, behind a confirmation; notice when the store was reset.
- Tests (`crates/e2e-tests/tests/devices.rs`): sign out and back in keeps the device and the store key, and nothing on the computer opens the store meanwhile; two accounts alternate in one profile without new enrolments; erasure revokes the device, erases the server part and forgets the account; a signed-out store opens again after a password change and after a recovery; a lost server part resets the store and says so; a device revoked while signed out is forgotten at sign-in. Unit tests cover the formats and the refusal of every wrong part, account and device.
