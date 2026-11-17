// SPDX-License-Identifier: AGPL-3.0-or-later

//! The public state of MLS groups in PostgreSQL (ADR 0019, section 14).
//!
//! A request that touches a group loads its rows ([`load`], which locks the
//! group's row until the transaction ends), lets `tavern-crypto` check and
//! merge what it must on a [`PublicState`], and writes back the rows that
//! changed ([`save`]) in the transaction that moves the epoch. Both [`save`]
//! and [`insert`] use the state up, and [`save`] writes only over the
//! revision it loaded. OpenMLS runs on the loaded rows in memory,
//! synchronously, between the two.
//!
//! The server never decrypts anything here: it holds the public tree, the
//! group context and its own `Remove` proposals.

use std::collections::HashMap;

use sqlx::PgConnection;
use tavern_crypto::identity::{ID_LEN, IdentityPublicKey};
use tavern_crypto::mls::group_id::GroupIdentity;
use tavern_crypto::mls::public::{Change, Entry};
use tavern_crypto::mls::{LeafError, MlsError, PublicEntries, PublicState, Roster, VerifiedLeaf};
use uuid::Uuid;

/// A group's state could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// PostgreSQL failed.
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    /// The stored state is not readable, or OpenMLS refused it.
    #[error(transparent)]
    Mls(#[from] MlsError),
    /// The conversation already has this generation, or a later one: another
    /// device created or recreated the group first (`STALE_EPOCH` for the
    /// API, ADR 0019, sections 4 and 17).
    #[error("the conversation already has this group generation or a later one")]
    GenerationExists,
    /// The stored group does not match the state: another request saved it
    /// since the state was loaded, or the row is gone, or its epoch disagrees
    /// with its rows.
    #[error("the stored group does not match the state")]
    Inconsistent,
}

fn group_id(identity: GroupIdentity) -> Vec<u8> {
    identity.to_group_id().as_slice().to_vec()
}

fn epoch_of(state: &PublicState) -> Result<i64, StateError> {
    i64::try_from(state.epoch()).map_err(|_| StateError::Inconsistent)
}

async fn write_entry(
    conn: &mut PgConnection,
    group_id: &[u8],
    entry: Entry,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO mls_group_entries (group_id, kind, key, value) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (group_id, kind, key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(group_id)
    .bind(entry.kind)
    .bind(entry.key)
    .bind(entry.value)
    .execute(conn)
    .await?;
    Ok(())
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(error) if error.code().as_deref() == Some("23505"))
}

/// Stores the state of a new group generation, built by
/// [`PublicState::create`] with the GroupInfo it checked, and deletes the
/// conversation's earlier generations with their rows (ADR 0019, section 12:
/// the server keeps the current state only). Creations of one conversation
/// take turns on a lock held until the transaction ends; the one that comes
/// second gets [`StateError::GenerationExists`].
pub async fn insert(conn: &mut PgConnection, state: PublicState) -> Result<(), StateError> {
    let identity = state.identity()?;
    let conversation = Uuid::from_bytes(identity.conversation_id);
    let generation = i64::from(identity.generation);
    // Until the conversation's own row exists (M2, task 7).
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("tavern.mls_groups:{conversation}"))
        .execute(&mut *conn)
        .await?;
    let later: Option<i64> = sqlx::query_scalar(
        "SELECT generation FROM mls_groups WHERE conversation_id = $1 AND generation >= $2 \
         LIMIT 1",
    )
    .bind(conversation)
    .bind(generation)
    .fetch_optional(&mut *conn)
    .await?;
    if later.is_some() {
        return Err(StateError::GenerationExists);
    }
    sqlx::query("DELETE FROM mls_groups WHERE conversation_id = $1 AND generation < $2")
        .bind(conversation)
        .bind(generation)
        .execute(&mut *conn)
        .await?;

    let id = group_id(identity);
    sqlx::query(
        "INSERT INTO mls_groups (group_id, conversation_id, generation, epoch, group_info) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&id)
    .bind(conversation)
    .bind(generation)
    .bind(epoch_of(&state)?)
    .bind(state.group_info())
    .execute(&mut *conn)
    .await
    .map_err(|error| {
        // A writer that did not take the lock: the same answer.
        if is_unique_violation(&error) {
            StateError::GenerationExists
        } else {
            StateError::Database(error)
        }
    })?;
    for entry in state.entries().entries() {
        write_entry(conn, &id, entry).await?;
    }
    Ok(())
}

/// A group's state as [`load`] read it, with the revision of its row: what
/// [`save`] writes back, provided no other request saved the group since.
#[derive(Debug)]
pub struct LoadedState {
    /// The state, to check and merge commits and removals on.
    pub state: PublicState,
    identity: GroupIdentity,
    revision: i64,
}

/// Loads a group's state, and locks its row until the transaction ends: one
/// request at a time moves a group's epoch or changes its proposals (ADR
/// 0019, sections 7 and 14).
pub async fn load(
    conn: &mut PgConnection,
    identity: GroupIdentity,
) -> Result<Option<LoadedState>, StateError> {
    let id = group_id(identity);
    let row: Option<(i64, i64, Vec<u8>)> = sqlx::query_as(
        "SELECT epoch, revision, group_info FROM mls_groups WHERE group_id = $1 FOR UPDATE",
    )
    .bind(&id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((epoch, revision, group_info)) = row else {
        return Ok(None);
    };
    let rows: Vec<(i16, Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT kind, key, value FROM mls_group_entries WHERE group_id = $1")
            .bind(&id)
            .fetch_all(&mut *conn)
            .await?;
    let entries = PublicEntries::load(
        identity,
        rows.into_iter()
            .map(|(kind, key, value)| Entry { kind, key, value }),
    )?;
    let state = PublicState::load(identity, entries, group_info)?;
    if epoch_of(&state)? != epoch {
        return Err(StateError::Inconsistent);
    }
    Ok(Some(LoadedState {
        state,
        identity,
        revision,
    }))
}

/// Writes back what changed in a state [`load`] returned: its epoch, its
/// latest GroupInfo and the rows that changed. The state is used up: after a
/// failure, the request loads the group again rather than reuse a state
/// whose changes were taken. Refused if another request saved the group
/// since the state was loaded: every save moves the row's revision, so a
/// proposal stored in between, which leaves the epoch where it was, counts
/// too (ADR 0019, section 14).
pub async fn save(conn: &mut PgConnection, loaded: LoadedState) -> Result<(), StateError> {
    let LoadedState {
        state,
        identity,
        revision,
    } = loaded;
    if state.identity()? != identity {
        return Err(StateError::Inconsistent);
    }
    let id = group_id(identity);
    let updated = sqlx::query(
        "UPDATE mls_groups \
         SET epoch = $2, group_info = $3, revision = revision + 1, updated_at = now() \
         WHERE group_id = $1 AND revision = $4",
    )
    .bind(&id)
    .bind(epoch_of(&state)?)
    .bind(state.group_info())
    .bind(revision)
    .execute(&mut *conn)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(StateError::Inconsistent);
    }
    for change in state.entries().take_changes() {
        match change {
            Change::Write(entry) => write_entry(conn, &id, entry).await?,
            Change::Delete { kind, key } => {
                sqlx::query(
                    "DELETE FROM mls_group_entries WHERE group_id = $1 AND kind = $2 AND key = $3",
                )
                .bind(&id)
                .bind(kind)
                .bind(key)
                .execute(&mut *conn)
                .await?;
            }
        }
    }
    Ok(())
}

/// What the server trusts for a conversation's leaves (ADR 0019, section 2):
/// the participants' identity keys from `users`, and their devices that are
/// not revoked, each with the key and the certificate it enrolled with. A
/// leaf must be one of those devices with exactly that key and certificate:
/// the identity key could certify another key under a device's id, the
/// server alone knows which key enrolled. Devices that stayed away longer
/// than the inactivity period join this rule with
/// `TAVERN_DEVICE_INACTIVE_DAYS` (M2, tasks 8 and 9).
#[derive(Debug, Clone, Default)]
pub struct ServerRoster {
    identity_keys: HashMap<[u8; ID_LEN], IdentityPublicKey>,
    enrolled: HashMap<VerifiedLeaf, (Vec<u8>, Vec<u8>)>,
}

impl ServerRoster {
    /// The roster of a conversation between `participants`. A disabled
    /// account has no active device.
    pub async fn load(conn: &mut PgConnection, participants: &[Uuid]) -> Result<Self, StateError> {
        let keys: Vec<(Uuid, Vec<u8>)> =
            sqlx::query_as("SELECT id, identity_key FROM users WHERE id = ANY($1)")
                .bind(participants)
                .fetch_all(&mut *conn)
                .await?;
        let devices: Vec<(Uuid, Uuid, Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT d.user_id, d.id, d.signature_key, d.certificate \
             FROM devices d JOIN users u ON u.id = d.user_id \
             WHERE d.user_id = ANY($1) AND d.revoked_at IS NULL AND u.disabled_at IS NULL",
        )
        .bind(participants)
        .fetch_all(&mut *conn)
        .await?;
        let mut identity_keys = HashMap::new();
        for (user, key) in keys {
            let key = IdentityPublicKey::from_bytes(&key)
                .map_err(|_| StateError::Mls(MlsError::Malformed))?;
            identity_keys.insert(*user.as_bytes(), key);
        }
        Ok(Self {
            identity_keys,
            enrolled: devices
                .into_iter()
                .map(|(user, device, signature_key, certificate)| {
                    (
                        VerifiedLeaf {
                            user_id: *user.as_bytes(),
                            device_id: *device.as_bytes(),
                        },
                        (signature_key, certificate),
                    )
                })
                .collect(),
        })
    }
}

impl Roster for ServerRoster {
    fn identity_key(&self, user_id: &[u8; ID_LEN]) -> Option<IdentityPublicKey> {
        self.identity_keys.get(user_id).copied()
    }

    fn check_device(
        &self,
        device: &VerifiedLeaf,
        signature_key: &[u8],
        certificate: &[u8],
    ) -> Result<(), LeafError> {
        let (enrolled_key, enrolled_certificate) =
            self.enrolled.get(device).ok_or(LeafError::InactiveDevice)?;
        if enrolled_key.as_slice() != signature_key
            || enrolled_certificate.as_slice() != certificate
        {
            return Err(LeafError::NotEnrolled);
        }
        Ok(())
    }
}
