//! Database bootstrap: pool creation, migrations, and the periodic cleanup
//! of expired sessions, registration requests and login states.

use std::time::Duration;

use sqlx::SqlitePool;
use sqlx::migrate::MigrateError;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use tracing::{debug, warn};

use crate::clock::unix_now;

/// Sliding session lifetime: 30 days of inactivity.
pub const SESSION_LIFETIME_SECS: i64 = 30 * 24 * 60 * 60;
/// Unapproved registration requests are dropped after one hour.
pub const PENDING_LIFETIME_SECS: i64 = 60 * 60;
/// In-flight OIDC logins expire after 10 minutes.
pub const OIDC_STATE_LIFETIME_SECS: i64 = 10 * 60;
/// A browser that completed an admin SSO login once keeps the
/// auto-redirect marker for a year.
pub const ADMIN_MARKER_LIFETIME_SECS: i64 = 365 * 24 * 60 * 60;

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

/// Spawn the housekeeping task: clean expired rows now, then every hour.
pub fn spawn_cleanup_task(pool: SqlitePool) {
    tokio::spawn(async move {
        loop {
            match cleanup_once(&pool).await {
                Ok(counts) => {
                    debug!(
                        sessions = counts.sessions,
                        pending_users = counts.pending_users,
                        oidc_logins = counts.oidc_logins,
                        "cleaned expired rows"
                    );
                }
                Err(source) => warn!("could not clean expired rows: {source}"),
            }
            tokio::time::sleep(Duration::from_hours(1)).await;
        }
    });
}

struct CleanupCounts {
    sessions: u64,
    pending_users: u64,
    oidc_logins: u64,
}

async fn cleanup_once(pool: &SqlitePool) -> Result<CleanupCounts, sqlx::Error> {
    let now = unix_now();
    let sessions = sqlx::query!("DELETE FROM sessions WHERE expires <= ?", now)
        .execute(pool)
        .await?
        .rows_affected();
    let pending_users = sqlx::query!(
        "DELETE FROM pending_users WHERE created <= ?",
        now.saturating_sub(PENDING_LIFETIME_SECS)
    )
    .execute(pool)
    .await?
    .rows_affected();
    let oidc_logins = sqlx::query!(
        "DELETE FROM oidc_logins WHERE expires <= ?",
        now.saturating_sub(OIDC_STATE_LIFETIME_SECS)
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(CleanupCounts {
        sessions,
        pending_users,
        oidc_logins,
    })
}
