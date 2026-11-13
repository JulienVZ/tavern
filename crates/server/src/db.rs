// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL connection pool and migrations.

use std::time::Duration;

use sqlx::PgPool;
use sqlx::migrate::{MigrateError, Migrator};
use sqlx::postgres::PgPoolOptions;

/// Migrations embedded in the binary at compile time.
static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long start-up keeps retrying while the database is not reachable yet.
const CONNECT_DEADLINE: Duration = Duration::from_secs(30);
const CONNECT_RETRY_DELAY: Duration = Duration::from_secs(2);

/// The database could not be opened at start-up.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// PostgreSQL refused the user name or password.
    ///
    /// The usual cause on a self-hosted instance: `.env` was regenerated while
    /// the PostgreSQL volume still holds the previous password. PostgreSQL only
    /// reads `POSTGRES_PASSWORD` when it initialises an empty volume, so its
    /// own health check stays green while every connection is refused.
    #[error(
        "PostgreSQL rejected the credentials (authentication failed).\n\
         Likely cause: the password in deploy/.env is not the one the database volume was \
         created with. This happens when .env is regenerated or replaced while the \
         PostgreSQL volume is kept.\n\
         Fix: restore the .env that belongs to this database (it is part of every backup made \
         by backup.sh), or set the old password again in POSTGRES_PASSWORD. On an instance \
         with no data to keep, `docker compose down -v` deletes the volume so that it is \
         recreated with the current password."
    )]
    AuthenticationFailed,
    /// The role or the database named in the URL does not exist.
    #[error(
        "PostgreSQL does not know the role or database named in the connection URL. \
         Check POSTGRES_USER and POSTGRES_DB in deploy/.env against the existing volume."
    )]
    UnknownRoleOrDatabase,
    /// The database stayed unreachable for the whole start-up deadline.
    #[error("PostgreSQL is unreachable: {0}")]
    Unreachable(#[source] sqlx::Error),
    /// Any other failure.
    #[error("cannot open the PostgreSQL connection pool: {0}")]
    Other(#[source] sqlx::Error),
}

/// How a connection failure is handled at start-up.
#[derive(Debug, PartialEq, Eq)]
enum Failure {
    /// Wrong user name or password. Retrying cannot help.
    Authentication,
    /// Unknown role or database. Retrying cannot help.
    UnknownRoleOrDatabase,
    /// The server is not accepting connections yet. Worth retrying.
    Transient,
    /// Anything else.
    Other,
}

/// Classifies a failure from its SQLSTATE code, when it has one.
///
/// Codes: <https://www.postgresql.org/docs/current/errcodes-appendix.html>.
fn classify(sqlstate: Option<&str>, is_io_or_timeout: bool) -> Failure {
    match sqlstate {
        // invalid_password, invalid_authorization_specification
        Some("28P01" | "28000") => Failure::Authentication,
        // invalid_catalog_name (unknown database)
        Some("3D000") => Failure::UnknownRoleOrDatabase,
        // cannot_connect_now (starting up), too_many_connections
        Some("57P03" | "53300") => Failure::Transient,
        Some(_) => Failure::Other,
        None if is_io_or_timeout => Failure::Transient,
        None => Failure::Other,
    }
}

fn classify_error(error: &sqlx::Error) -> Failure {
    match error {
        sqlx::Error::Database(db) => classify(db.code().as_deref(), false),
        sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut => classify(None, true),
        _ => classify(None, false),
    }
}

/// Opens a connection pool and checks that the database answers.
///
/// Retries for a short while when PostgreSQL is still starting. Fails at once,
/// with an explanation, when the credentials are refused.
pub async fn connect(database_url: &str, max_connections: u32) -> Result<PgPool, ConnectError> {
    let deadline = tokio::time::Instant::now() + CONNECT_DEADLINE;

    loop {
        let attempt = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(ACQUIRE_TIMEOUT)
            .connect(database_url)
            .await;

        let error = match attempt {
            Ok(pool) => return Ok(pool),
            Err(error) => error,
        };

        match classify_error(&error) {
            Failure::Authentication => return Err(ConnectError::AuthenticationFailed),
            Failure::UnknownRoleOrDatabase => return Err(ConnectError::UnknownRoleOrDatabase),
            Failure::Other => return Err(ConnectError::Other(error)),
            Failure::Transient => {
                if tokio::time::Instant::now() + CONNECT_RETRY_DELAY >= deadline {
                    return Err(ConnectError::Unreachable(error));
                }
                tracing::warn!("PostgreSQL is not reachable yet, retrying");
                tokio::time::sleep(CONNECT_RETRY_DELAY).await;
            }
        }
    }
}

/// Applies every pending migration.
pub async fn migrate(pool: &PgPool) -> Result<(), MigrateError> {
    MIGRATOR.run(pool).await
}

/// Returns `true` when the database answers a trivial query in time.
pub async fn is_healthy(pool: &PgPool) -> bool {
    const TIMEOUT: Duration = Duration::from_secs(2);

    matches!(
        tokio::time::timeout(TIMEOUT, sqlx::query("SELECT 1").execute(pool)).await,
        Ok(Ok(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentication_failures_are_not_retried() {
        assert_eq!(classify(Some("28P01"), false), Failure::Authentication);
        assert_eq!(classify(Some("28000"), false), Failure::Authentication);
    }

    #[test]
    fn unknown_database_is_reported_as_such() {
        assert_eq!(
            classify(Some("3D000"), false),
            Failure::UnknownRoleOrDatabase
        );
    }

    #[test]
    fn start_up_and_network_failures_are_retried() {
        assert_eq!(classify(Some("57P03"), false), Failure::Transient);
        assert_eq!(classify(None, true), Failure::Transient);
    }

    #[test]
    fn other_failures_are_not_retried() {
        assert_eq!(classify(Some("42601"), false), Failure::Other);
        assert_eq!(classify(None, false), Failure::Other);
    }

    #[test]
    fn authentication_error_explains_cause_and_fix() {
        let message = ConnectError::AuthenticationFailed.to_string();

        assert!(message.contains("authentication failed"));
        assert!(message.contains("deploy/.env"));
        assert!(message.contains("backup"));
        assert!(message.contains("docker compose down -v"));
    }
}
