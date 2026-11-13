// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL connection pool and migrations.

use std::time::Duration;

use sqlx::PgPool;
use sqlx::migrate::{MigrateError, Migrator};
use sqlx::postgres::PgPoolOptions;

/// Migrations embedded in the binary at compile time.
static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

/// Opens a connection pool and checks that the database answers.
pub async fn connect(database_url: &str, max_connections: u32) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(ACQUIRE_TIMEOUT)
        .connect(database_url)
        .await
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
