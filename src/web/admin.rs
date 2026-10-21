//! Admin-only API: the registration queue and the user list with the ban
//! switch. Every route here sits behind the admin middleware, so user 0 is
//! the only caller.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use serde_json::json;

use crate::clock::unix_now;
use crate::db::PENDING_LIFETIME_SECS;
use crate::web::AppState;
use crate::web::auth::{admin_middleware, db_error, json_error};

/// Build the admin routes under `/api/admin`.
pub fn admin_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/pending", get(pending_list))
        .route("/pending/{id}/approve", post(pending_approve))
        .route("/pending/{id}/deny", post(pending_deny))
        .route("/users", get(user_list))
        .route("/users/{id}/ban", post(ban))
        .route("/users/{id}/unban", post(unban))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            admin_middleware,
        ))
        .with_state(state)
}

#[derive(Debug, Serialize)]
struct PendingEntry {
    telegram_id: i64,
    name: Option<String>,
    username: Option<String>,
    created: i64,
}

/// `GET /api/admin/pending`: live registration requests, oldest first.
async fn pending_list(State(state): State<AppState>) -> Response {
    struct Row {
        telegram_id: i64,
        name: Option<String>,
        username: Option<String>,
        created: i64,
    }
    let cutoff = unix_now().saturating_sub(PENDING_LIFETIME_SECS);
    let rows = sqlx::query_as!(
        Row,
        "SELECT telegram_id, name, username, created FROM pending_users
         WHERE created > ? ORDER BY created",
        cutoff
    )
    .fetch_all(&state.db)
    .await;
    let rows = match rows {
        Ok(rows) => rows,
        Err(source) => return db_error(&source),
    };
    let entries: Vec<PendingEntry> = rows
        .into_iter()
        .map(|row| PendingEntry {
            telegram_id: row.telegram_id,
            name: row.name,
            username: row.username,
            created: row.created,
        })
        .collect();
    (StatusCode::OK, Json(entries)).into_response()
}

/// `POST /api/admin/pending/{telegram_id}/approve`: create the user and
/// drop the request. The @handle is the preferred display name.
async fn pending_approve(State(state): State<AppState>, Path(telegram_id): Path<i64>) -> Response {
    struct Row {
        name: Option<String>,
        username: Option<String>,
        created: i64,
    }
    struct ExistingId {
        id: i64,
    }
    let row = sqlx::query_as!(
        Row,
        "SELECT name, username, created FROM pending_users WHERE telegram_id = ?",
        telegram_id
    )
    .fetch_optional(&state.db)
    .await;
    let row = match row {
        Ok(Some(row)) => row,
        Ok(None) => {
            return json_error(StatusCode::NOT_FOUND, "no such registration request");
        }
        Err(source) => return db_error(&source),
    };
    if row.created <= unix_now().saturating_sub(PENDING_LIFETIME_SECS) {
        return json_error(
            StatusCode::NOT_FOUND,
            "this registration request has expired",
        );
    }

    // An account may already exist for this telegram id, for example when
    // the request was approved from a second open panel; treat that as
    // success either way, the request always goes.
    let existing = sqlx::query_as!(
        ExistingId,
        "SELECT id FROM users WHERE telegram_id = ?",
        telegram_id
    )
    .fetch_optional(&state.db)
    .await;
    let user_id = match existing {
        Ok(Some(ExistingId { id })) => id,
        Ok(None) => {
            let display = row
                .username
                .clone()
                .filter(|value| !value.is_empty())
                .or_else(|| row.name.clone());
            let inserted = sqlx::query!(
                "INSERT INTO users (telegram_id, name) VALUES (?, ?)",
                telegram_id,
                display,
            )
            .execute(&state.db)
            .await;
            match inserted {
                Ok(result) => result.last_insert_rowid(),
                Err(source) => return db_error(&source),
            }
        }
        Err(source) => return db_error(&source),
    };

    let deleted = sqlx::query!(
        "DELETE FROM pending_users WHERE telegram_id = ?",
        telegram_id
    )
    .execute(&state.db)
    .await;
    if let Err(source) = deleted {
        return db_error(&source);
    }
    (StatusCode::CREATED, Json(json!({ "id": user_id }))).into_response()
}

/// `POST /api/admin/pending/{telegram_id}/deny`: drop the request without
/// creating a user. The same account may queue again later.
async fn pending_deny(State(state): State<AppState>, Path(telegram_id): Path<i64>) -> Response {
    let deleted = sqlx::query!(
        "DELETE FROM pending_users WHERE telegram_id = ?",
        telegram_id
    )
    .execute(&state.db)
    .await;
    match deleted {
        Ok(result) if result.rows_affected() > 0 => {
            (StatusCode::OK, Json(json!({ "status": "denied" }))).into_response()
        }
        Ok(_) => json_error(StatusCode::NOT_FOUND, "no such registration request"),
        Err(source) => db_error(&source),
    }
}

#[derive(Debug, Serialize)]
struct UserEntry {
    id: i64,
    name: Option<String>,
    telegram_id: Option<i64>,
    banned: bool,
}

/// `GET /api/admin/users`: every account, admin included.
async fn user_list(State(state): State<AppState>) -> Response {
    struct Row {
        id: i64,
        name: Option<String>,
        telegram_id: Option<i64>,
        banned: bool,
    }
    let rows = sqlx::query_as!(
        Row,
        r#"SELECT id, name, telegram_id, banned AS "banned: bool" FROM users ORDER BY id"#
    )
    .fetch_all(&state.db)
    .await;
    let rows = match rows {
        Ok(rows) => rows,
        Err(source) => return db_error(&source),
    };
    let entries: Vec<UserEntry> = rows
        .into_iter()
        .map(|row| UserEntry {
            id: row.id,
            name: row.name,
            telegram_id: row.telegram_id,
            banned: row.banned,
        })
        .collect();
    (StatusCode::OK, Json(entries)).into_response()
}

/// `POST /api/admin/users/{id}/ban`: flag the account and kill all of its
/// sessions right away, so the ban is effective immediately on every
/// device. The admin (user 0) cannot be banned.
async fn ban(State(state): State<AppState>, Path(user_id): Path<i64>) -> Response {
    if user_id == 0 {
        return json_error(StatusCode::BAD_REQUEST, "the admin cannot be banned");
    }
    let updated = sqlx::query!(
        "UPDATE users SET banned = 1 WHERE id = ? AND id != 0",
        user_id
    )
    .execute(&state.db)
    .await;
    let updated = match updated {
        Ok(result) => result,
        Err(source) => return db_error(&source),
    };
    if updated.rows_affected() == 0 {
        return json_error(StatusCode::NOT_FOUND, "no such user");
    }
    let wiped = sqlx::query!("DELETE FROM sessions WHERE user_id = ?", user_id)
        .execute(&state.db)
        .await;
    if let Err(source) = wiped {
        return db_error(&source);
    }
    (StatusCode::OK, Json(json!({ "status": "banned" }))).into_response()
}

/// `POST /api/admin/users/{id}/unban`: clear the flag. The telegram binding
/// is untouched, so the user can simply log in again, no re-approval.
async fn unban(State(state): State<AppState>, Path(user_id): Path<i64>) -> Response {
    let updated = sqlx::query!(
        "UPDATE users SET banned = 0 WHERE id = ? AND id != 0",
        user_id
    )
    .execute(&state.db)
    .await;
    match updated {
        Ok(result) if result.rows_affected() > 0 => {
            (StatusCode::OK, Json(json!({ "status": "unbanned" }))).into_response()
        }
        Ok(_) => json_error(StatusCode::NOT_FOUND, "no such user"),
        Err(source) => db_error(&source),
    }
}
