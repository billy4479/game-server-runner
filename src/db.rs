//! Database bootstrap: pool creation, migrations, the admin bootstrap token,
//! and the periodic cleanup of expired sessions and tokens.

use std::time::Duration;

use sqlx::SqlitePool;
use sqlx::migrate::MigrateError;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use tracing::{debug, info, warn};

use crate::clock::unix_now;
use crate::tokens::generate_token;

/// Errors that can occur while opening the database.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// The database could not be opened or a query failed.
    #[error("database: {0}")]
    Connect(#[from] sqlx::Error),
    /// The embedded migrations could not be applied.
    #[error("database migration: {0}")]
    Migrate(#[from] MigrateError),
}

/// Open (creating if needed) the `SQLite` database and apply migrations.
///
/// Journal mode is set explicitly: sqlx 0.9 no longer enables WAL by default.
///
/// # Errors
/// Returns [`DbError`] if the pool cannot be created or migrations fail.
pub async fn init(db_path: &str) -> Result<SqlitePool, DbError> {
    let options = SqliteConnectOptions::new()
        .filename(db_path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .idle_timeout(Duration::from_mins(1))
        .connect_with(options)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

/// Make sure user 0 has a usable invitation token, generating a
/// never-expiring one and logging it otherwise. mc-runner parity.
///
/// # Errors
/// Returns [`DbError`] if the queries fail.
pub async fn ensure_admin_token(pool: &SqlitePool) -> Result<(), DbError> {
    let now = unix_now();
    let row = sqlx::query!(
        r#"SELECT COUNT(*) AS "count: i64" FROM tokens
           WHERE user_id = 0 AND kind = 'invitation'
             AND (expires IS NULL OR expires > ?)"#,
        now
    )
    .fetch_one(pool)
    .await?;
    if row.count > 0 {
        return Ok(());
    }

    let (token, hash) = generate_token();
    sqlx::query!(
        r#"INSERT INTO tokens (token_hash, kind, user_id, expires)
           VALUES (?, 'invitation', 0, NULL)"#,
        &hash[..]
    )
    .execute(pool)
    .await?;
    info!("admin invitation token: {token}");
    Ok(())
}

/// Spawn the housekeeping task: clean expired rows now, then every hour.
pub fn spawn_cleanup_task(pool: SqlitePool) {
    tokio::spawn(async move {
        loop {
            match cleanup_once(&pool).await {
                Ok((sessions, tokens)) => {
                    debug!(sessions, tokens, "cleaned expired sessions and tokens");
                }
                Err(source) => warn!("could not clean expired rows: {source}"),
            }
            tokio::time::sleep(Duration::from_hours(1)).await;
        }
    });
}

async fn cleanup_once(pool: &SqlitePool) -> Result<(u64, u64), sqlx::Error> {
    let now = unix_now();
    let sessions = sqlx::query!("DELETE FROM sessions WHERE expires <= ?", now)
        .execute(pool)
        .await?
        .rows_affected();
    let tokens = sqlx::query!(
        "DELETE FROM tokens WHERE expires IS NOT NULL AND expires <= ?",
        now
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok((sessions, tokens))
}
