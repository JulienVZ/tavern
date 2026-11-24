// SPDX-License-Identifier: AGPL-3.0-or-later

//! Security notices: what every device of an account must tell its user.
//!
//! A notice is recorded when something security-relevant happens to an
//! account (see [`NoticeKind`]). It is pushed to the devices that are
//! connected and listed again in `Ready` at each connection, until the device
//! acknowledges it: a device that was offline, or signed out, still learns
//! about it. See ADR 0016.
//!
//! A notice is a kind and a date. It never holds text, a device or an address.

use sqlx::PgConnection;
use tavern_protocol::gateway::v1 as proto;
use uuid::Uuid;

use crate::AppState;
use crate::error::ApiResult;
use crate::gateway::Event;
use crate::session::Session;

/// Days after which a notice is deleted, acknowledged or not.
pub const RETENTION_DAYS: i32 = 90;
/// Most notices listed in one `Ready`, oldest first.
pub const MAX_PENDING: i64 = 32;

/// Codes stored in `security_notices.kind`. Never renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i16)]
pub enum NoticeKind {
    /// An administrator disabled TOTP on the account.
    TotpDisabledByAdmin = 1,
    /// The password was changed.
    PasswordChanged = 2,
    /// The account was recovered with the recovery key.
    AccountRecovered = 3,
    /// A device of the account was revoked.
    DeviceRevoked = 4,
    /// The recovery key was replaced.
    RecoveryKeyReplaced = 5,
    /// The instance was restored from a backup ([`crate::restore`]):
    /// recorded for every account, with the date of the backup.
    InstanceRestored = 6,
}

impl NoticeKind {
    /// Every kind, for tests and documentation checks.
    pub const ALL: [Self; 6] = [
        Self::TotpDisabledByAdmin,
        Self::PasswordChanged,
        Self::AccountRecovered,
        Self::DeviceRevoked,
        Self::RecoveryKeyReplaced,
        Self::InstanceRestored,
    ];

    /// Kinds also shown to devices enrolled after the event, until one device
    /// of the account has acknowledged the notice.
    ///
    /// These are the kinds that no device of the account is known to have
    /// done, and that the user meets on any device without an explanation:
    /// with TOTP disabled, sign-in stops asking for a code; after a recovery
    /// the password no longer works and every device is signed out, and the
    /// user may well come back on a new computer. After a restore, every
    /// device is signed out, and one enrolled after the backup is unknown to
    /// the restored database: it is enrolled anew, after the notice. The
    /// other kinds are acknowledged at once by the device that acted.
    pub const SHOWN_TO_LATER_DEVICES: [Self; 3] = [
        Self::TotpDisabledByAdmin,
        Self::AccountRecovered,
        Self::InstanceRestored,
    ];

    fn from_db(value: i16) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| *kind as i16 == value)
    }

    /// The kind as sent to clients.
    pub fn to_proto(self) -> proto::SecurityNoticeKind {
        match self {
            Self::TotpDisabledByAdmin => proto::SecurityNoticeKind::TotpDisabledByAdmin,
            Self::PasswordChanged => proto::SecurityNoticeKind::PasswordChanged,
            Self::AccountRecovered => proto::SecurityNoticeKind::AccountRecovered,
            Self::DeviceRevoked => proto::SecurityNoticeKind::DeviceRevoked,
            Self::RecoveryKeyReplaced => proto::SecurityNoticeKind::RecoveryKeyReplaced,
            Self::InstanceRestored => proto::SecurityNoticeKind::InstanceRestored,
        }
    }
}

/// A recorded notice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Notice {
    /// Identifier, used to acknowledge it.
    pub id: Uuid,
    /// What happened.
    pub kind: NoticeKind,
    /// When, in milliseconds since the Unix epoch.
    pub created_at_ms: u64,
    /// [`NoticeKind::InstanceRestored`] only: when the restored backup was
    /// taken, in milliseconds since the Unix epoch, if the server knows.
    pub backup_taken_at_ms: Option<u64>,
}

impl Notice {
    /// The notice as sent to clients.
    pub fn to_proto(self) -> proto::SecurityNotice {
        proto::SecurityNotice {
            kind: self.kind.to_proto().into(),
            notice_id: self.id.as_bytes().to_vec(),
            created_at_ms: self.created_at_ms,
            backup_taken_at_ms: self.backup_taken_at_ms.unwrap_or_default(),
        }
    }
}

/// Stores a notice for `user_id`, inside the caller's transaction so that it
/// commits with the action it reports. Call [`publish`] after the commit.
///
/// `acting_device` is the device whose user just did the action: it does not
/// need to be told, so the notice is acknowledged for it at once.
pub async fn insert(
    db: &mut PgConnection,
    user_id: Uuid,
    kind: NoticeKind,
    acting_device: Option<Uuid>,
) -> ApiResult<Notice> {
    sqlx::query(
        "DELETE FROM security_notices \
         WHERE user_id = $1 AND created_at < now() - make_interval(days => $2)",
    )
    .bind(user_id)
    .bind(RETENTION_DAYS)
    .execute(&mut *db)
    .await?;

    let (id, created): (Uuid, i64) = sqlx::query_as(
        "INSERT INTO security_notices (user_id, kind) VALUES ($1, $2) \
         RETURNING id, (extract(epoch FROM created_at) * 1000)::bigint",
    )
    .bind(user_id)
    .bind(kind as i16)
    .fetch_one(&mut *db)
    .await?;

    if let Some(device_id) = acting_device {
        sqlx::query("INSERT INTO security_notice_acks (notice_id, device_id) VALUES ($1, $2)")
            .bind(id)
            .bind(device_id)
            .execute(&mut *db)
            .await?;
    }
    Ok(Notice {
        id,
        kind,
        created_at_ms: u64::try_from(created).unwrap_or_default(),
        backup_taken_at_ms: None,
    })
}

/// Pushes a stored notice to the connected devices of the account, except
/// the acting one. Devices that are not connected get it from `Ready`.
pub fn publish(state: &AppState, user_id: Uuid, notice: Notice, acting_device: Option<Uuid>) {
    state
        .gateway
        .notify_user(user_id, acting_device, Event::SecurityNotice(notice));
}

/// Stores a notice without pushing it: for actions that sign the other
/// devices out, which therefore read it from `Ready` once signed in again.
/// See [`insert`] for `acting_device`.
pub async fn store(
    state: &AppState,
    user_id: Uuid,
    kind: NoticeKind,
    acting_device: Option<Uuid>,
) -> ApiResult<Notice> {
    let mut tx = state.db.begin().await?;
    let notice = insert(&mut tx, user_id, kind, acting_device).await?;
    tx.commit().await?;
    Ok(notice)
}

/// Stores and pushes a notice. See [`insert`] for `acting_device`.
pub async fn record(
    state: &AppState,
    user_id: Uuid,
    kind: NoticeKind,
    acting_device: Option<Uuid>,
) -> ApiResult<Notice> {
    let notice = store(state, user_id, kind, acting_device).await?;
    publish(state, user_id, notice, acting_device);
    Ok(notice)
}

/// Notices of the account that the device of `session` has not acknowledged,
/// oldest first.
///
/// A device is not told about what happened before it was enrolled, except
/// for the kinds in [`NoticeKind::SHOWN_TO_LATER_DEVICES`], which it is told
/// about as long as no device of the account has acknowledged them.
pub async fn pending(state: &AppState, session: &Session) -> ApiResult<Vec<Notice>> {
    let later: Vec<i16> = NoticeKind::SHOWN_TO_LATER_DEVICES
        .iter()
        .map(|kind| *kind as i16)
        .collect();
    let rows: Vec<(Uuid, i16, i64, Option<i64>)> = sqlx::query_as(
        "SELECT n.id, n.kind, (extract(epoch FROM n.created_at) * 1000)::bigint, \
                (extract(epoch FROM n.backup_taken_at) * 1000)::bigint \
         FROM security_notices n JOIN devices me ON me.id = $2 \
         WHERE n.user_id = $1 \
           AND (n.created_at >= me.created_at \
                OR (n.kind = ANY($5) AND NOT EXISTS (SELECT 1 FROM security_notice_acks seen \
                                                     WHERE seen.notice_id = n.id))) \
           AND n.created_at >= now() - make_interval(days => $3) \
           AND NOT EXISTS (SELECT 1 FROM security_notice_acks a \
                           WHERE a.notice_id = n.id AND a.device_id = $2) \
         ORDER BY n.created_at, n.id LIMIT $4",
    )
    .bind(session.user_id)
    .bind(session.device_id)
    .bind(RETENTION_DAYS)
    .bind(MAX_PENDING)
    .bind(later)
    .fetch_all(&state.db)
    .await?;

    Ok(rows
        .into_iter()
        .filter_map(|(id, kind, created, backup)| {
            Some(Notice {
                id,
                kind: NoticeKind::from_db(kind)?,
                created_at_ms: u64::try_from(created).unwrap_or_default(),
                backup_taken_at_ms: backup.and_then(|at| u64::try_from(at).ok()),
            })
        })
        .collect())
}

/// Deletes the notices of one kind for an account, when what they report no
/// longer holds (TOTP was enabled again). Runs in the caller's transaction.
pub async fn resolve(db: &mut PgConnection, user_id: Uuid, kind: NoticeKind) -> ApiResult<()> {
    sqlx::query("DELETE FROM security_notices WHERE user_id = $1 AND kind = $2")
        .bind(user_id)
        .bind(kind as i16)
        .execute(db)
        .await?;
    Ok(())
}

/// Marks notices as shown on the device of `session`. Identifiers that are
/// unknown, or belong to another account, are ignored.
pub async fn acknowledge(state: &AppState, session: &Session, ids: &[Uuid]) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO security_notice_acks (notice_id, device_id) \
         SELECT n.id, $2 FROM security_notices n WHERE n.user_id = $1 AND n.id = ANY($3) \
         ON CONFLICT DO NOTHING",
    )
    .bind(session.user_id)
    .bind(session.device_id)
    .bind(ids)
    .execute(&state.db)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_keep_their_codes_and_match_the_protocol() {
        let codes: Vec<i16> = NoticeKind::ALL.iter().map(|kind| *kind as i16).collect();
        assert_eq!(codes, [1, 2, 3, 4, 5, 6]);
        for kind in NoticeKind::ALL {
            // Database and wire codes are the same numbers.
            assert_eq!(i32::from(kind as i16), i32::from(kind.to_proto()));
            assert_eq!(NoticeKind::from_db(kind as i16), Some(kind));
        }
        assert_eq!(NoticeKind::from_db(0), None);
        assert_eq!(NoticeKind::from_db(7), None);
    }
}
