// SPDX-License-Identifier: AGPL-3.0-or-later

//! The public state of MLS groups in PostgreSQL (ADR 0019, section 14).
//!
//! A request that touches a group loads its rows ([`load`], which locks the
//! group's row until the transaction ends), lets `tavern-crypto` check and
//! merge what it must on a [`PublicState`], and writes back the rows that
//! changed ([`save`]) in the transaction that moves the epoch. OpenMLS runs
//! on the loaded rows in memory, synchronously, between the two.
//!
//! The server never decrypts anything here: it holds the public tree, the
//! group context and its own `Remove` proposals.

use std::collections::{HashMap, HashSet};

use sqlx::PgConnection;
use tavern_crypto::identity::{ID_LEN, IdentityPublicKey};
use tavern_crypto::mls::group_id::GroupIdentity;
use tavern_crypto::mls::public::{Change, Entry};
use tavern_crypto::mls::{MlsError, PublicEntries, PublicState, Roster, VerifiedLeaf};
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
    /// The conversation already has this generation, or a later one.
    #[error("the conversation already has this group generation or a later one")]
    GenerationExists,
    /// The stored epoch and the state's disagree.
    #[error("the stored epoch does not match the group state")]
    Inconsistent,
}

/// A group as the server stored it.
#[derive(Debug)]
pub struct StoredGroup {
    /// Its public state.
    pub state: PublicState,
    /// The latest GroupInfo, for devices joining by external commit.
    pub group_info: Vec<u8>,
}

fn group_id(identity: GroupIdentity) -> Vec<u8> {
    identity.to_group_id().as_slice().to_vec()
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

/// Stores the state of a new group generation, built from its first
/// GroupInfo, and deletes the conversation's earlier generations with their
/// rows (ADR 0019, section 12: the server keeps the current state only).
pub async fn insert(
    conn: &mut PgConnection,
    state: &PublicState,
    group_info: &[u8],
) -> Result<(), StateError> {
    let identity = state.identity()?;
    let conversation = Uuid::from_bytes(identity.conversation_id);
    let generation = i64::from(identity.generation);
    let later: Option<i64> = sqlx::query_scalar(
        "SELECT generation FROM mls_groups WHERE conversation_id = $1 AND generation >= $2 \
         LIMIT 1 FOR UPDATE",
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
    let epoch = i64::try_from(state.epoch()).map_err(|_| StateError::Inconsistent)?;
    sqlx::query(
        "INSERT INTO mls_groups (group_id, conversation_id, generation, epoch, group_info) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&id)
    .bind(conversation)
    .bind(generation)
    .bind(epoch)
    .bind(group_info)
    .execute(&mut *conn)
    .await?;
    for entry in state.entries().entries() {
        write_entry(conn, &id, entry).await?;
    }
    // Stored whole: nothing left to write back.
    state.entries().take_changes();
    Ok(())
}

/// Loads a group's state, and locks its row until the transaction ends: one
/// request at a time moves a group's epoch (ADR 0019, section 7).
pub async fn load(
    conn: &mut PgConnection,
    identity: GroupIdentity,
) -> Result<Option<StoredGroup>, StateError> {
    let id = group_id(identity);
    let row: Option<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT epoch, group_info FROM mls_groups WHERE group_id = $1 FOR UPDATE")
            .bind(&id)
            .fetch_optional(&mut *conn)
            .await?;
    let Some((epoch, group_info)) = row else {
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
    let state = PublicState::load(identity, entries)?;
    if i64::try_from(state.epoch()).ok() != Some(epoch) {
        return Err(StateError::Inconsistent);
    }
    Ok(Some(StoredGroup { state, group_info }))
}

/// Writes back what changed in a loaded state: its rows, its epoch, and the
/// new GroupInfo when a commit was merged.
pub async fn save(
    conn: &mut PgConnection,
    state: &PublicState,
    group_info: Option<&[u8]>,
) -> Result<(), StateError> {
    let id = group_id(state.identity()?);
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
    let epoch = i64::try_from(state.epoch()).map_err(|_| StateError::Inconsistent)?;
    sqlx::query(
        "UPDATE mls_groups SET epoch = $2, group_info = COALESCE($3, group_info), \
         updated_at = now() WHERE group_id = $1",
    )
    .bind(&id)
    .bind(epoch)
    .bind(group_info)
    .execute(conn)
    .await?;
    Ok(())
}

/// What the server trusts for a conversation's leaves (ADR 0019, section 2):
/// the participants' identity keys from `users`, and their devices that are
/// not revoked. Devices that stayed away longer than the inactivity period
/// join this rule with `TAVERN_DEVICE_INACTIVE_DAYS` (M2, tasks 8 and 9).
#[derive(Debug, Clone, Default)]
pub struct ServerRoster {
    identity_keys: HashMap<[u8; ID_LEN], IdentityPublicKey>,
    active: HashSet<VerifiedLeaf>,
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
        let devices: Vec<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT d.user_id, d.id FROM devices d JOIN users u ON u.id = d.user_id \
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
            active: devices
                .into_iter()
                .map(|(user, device)| VerifiedLeaf {
                    user_id: *user.as_bytes(),
                    device_id: *device.as_bytes(),
                })
                .collect(),
        })
    }
}

impl Roster for ServerRoster {
    fn identity_key(&self, user_id: &[u8; ID_LEN]) -> Option<IdentityPublicKey> {
        self.identity_keys.get(user_id).copied()
    }

    fn accepts_device(&self, device: &VerifiedLeaf) -> bool {
        self.active.contains(device)
    }
}
