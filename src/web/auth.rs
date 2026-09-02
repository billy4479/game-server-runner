//! Auth endpoints and middleware: invite-based registration, login tokens,
//! and sessions that rotate and slide their expiry on every authenticated
//! request. Error bodies are small JSON; the frontend only reads the status.

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use serde_json::json;
use sqlx::SqlitePool;
use tracing::error;

use crate::clock::unix_now;
use crate::tokens::{generate_token, hash_from_b64};
use crate::web::AppState;

/// Sliding session lifetime: 30 days of inactivity.
const SESSION_LIFETIME_SECS: i64 = 30 * 24 * 60 * 60;
/// Invitation tokens expire after 3 days.
const INVITE_LIFETIME_SECS: i64 = 3 * 24 * 60 * 60;
/// Login tokens are one-shot and expire after 1 hour.
const LOGIN_TOKEN_LIFETIME_SECS: i64 = 60 * 60;

/// Attributes shared by the set and clear cookie; only the value and
/// Max-Age differ.
const COOKIE_ATTRIBUTES: &str = "Path=/api; HttpOnly; SameSite=Lax; Secure";

/// Build the auth routes under `/api/auth`.
pub fn auth_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route(
            "/invite",
            post(invite).route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                admin_middleware,
            )),
        )
        .route("/register", post(register))
        .route("/login", post(login))
        .route(
            "/addDevice",
            post(add_device).route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            )),
        )
        .route(
            "/me",
            get(me).route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            )),
        )
        .route(
            "/logout",
            delete(logout).route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            )),
        )
        .with_state(state)
}

/// The authenticated user, inserted into request extensions by the auth
/// middleware.
#[derive(Debug, Clone)]
struct AuthedUser {
    id: i64,
    name: Option<String>,
}

/// Hash of the session token as it arrived on the request, before rotation.
/// Logout must delete the session by this hash: after rotation the cookie
/// carries the new token instead.
#[derive(Debug, Clone)]
struct SessionTokenHash([u8; 32]);

/// Everything the middleware learned about the request's session.
struct Authenticated {
    user: AuthedUser,
    old_hash: [u8; 32],
    new_cookie: HeaderValue,
}

struct SessionRow {
    user_id: i64,
    name: Option<String>,
    expires: i64,
}

struct TokenRow {
    user_id: i64,
    expires: Option<i64>,
}

struct UserIdRow {
    id: i64,
}

/// Require a valid session cookie, rotating it on the way through.
pub async fn auth_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    match authenticate(&state.db, request.headers()).await {
        Ok(auth) => run_with_auth(request, next, auth).await,
        Err(response) => response,
    }
}

/// Like [`auth_middleware`], but only user 0 gets through.
pub async fn admin_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    match authenticate(&state.db, request.headers()).await {
        Ok(auth) if auth.user.id == 0 => run_with_auth(request, next, auth).await,
        // The session was already rotated in the database, so the 403 must
        // still hand the caller its new cookie.
        Ok(auth) => {
            let mut response = json_error(StatusCode::FORBIDDEN, "admin access required");
            response
                .headers_mut()
                .append(header::SET_COOKIE, auth.new_cookie);
            response
        }
        Err(response) => response,
    }
}

async fn run_with_auth(mut request: Request, next: Next, auth: Authenticated) -> Response {
    request.extensions_mut().insert(auth.user);
    request
        .extensions_mut()
        .insert(SessionTokenHash(auth.old_hash));
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .append(header::SET_COOKIE, auth.new_cookie);
    response
}

async fn authenticate(db: &SqlitePool, headers: &HeaderMap) -> Result<Authenticated, Response> {
    let Some(token) = cookie_value(headers, "auth") else {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "missing session cookie",
        ));
    };
    let Ok(old_hash) = hash_from_b64(token) else {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "malformed session cookie",
        ));
    };

    let now = unix_now();
    let row = sqlx::query_as!(
        SessionRow,
        "SELECT s.user_id, u.name, s.expires
         FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ?",
        &old_hash[..]
    )
    .fetch_optional(db)
    .await
    .map_err(|source| db_error(&source))?;
    let Some(row) = row else {
        return Err(json_error(StatusCode::UNAUTHORIZED, "invalid session"));
    };
    if row.expires <= now {
        // Not deleted here; the cleanup task owns that.
        return Err(json_error(StatusCode::UNAUTHORIZED, "session expired"));
    }

    // One write does both the rotation and the sliding expiry. Losing the
    // race means another request already rotated this session: treat this
    // cookie as invalid.
    let (new_token, new_hash) = generate_token();
    let expires = now.saturating_add(SESSION_LIFETIME_SECS);
    let updated = sqlx::query!(
        "UPDATE sessions SET token_hash = ?, expires = ? WHERE token_hash = ?",
        &new_hash[..],
        expires,
        &old_hash[..]
    )
    .execute(db)
    .await
    .map_err(|source| db_error(&source))?;
    if updated.rows_affected() == 0 {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "session already rotated",
        ));
    }

    let Some(new_cookie) = cookie_header(&new_token, SESSION_LIFETIME_SECS) else {
        return Err(internal_error());
    };
    Ok(Authenticated {
        user: AuthedUser {
            id: row.user_id,
            name: row.name,
        },
        old_hash,
        new_cookie,
    })
}

/// `POST /api/auth/invite`: create a user row and a 3-day invitation token
/// for it. Admin only.
async fn invite(State(state): State<AppState>) -> Result<Response, Response> {
    let (token, hash) = generate_token();
    let expires = unix_now().saturating_add(INVITE_LIFETIME_SECS);

    let mut tx = state.db.begin().await.map_err(|source| db_error(&source))?;
    let user = sqlx::query!(r#"INSERT INTO users (name) VALUES (NULL) RETURNING id"#)
        .fetch_one(&mut *tx)
        .await
        .map_err(|source| db_error(&source))?;
    sqlx::query!(
        r#"INSERT INTO tokens (token_hash, kind, user_id, expires)
           VALUES (?, 'invitation', ?, ?)"#,
        &hash[..],
        user.id,
        expires
    )
    .execute(&mut *tx)
    .await
    .map_err(|source| db_error(&source))?;
    tx.commit().await.map_err(|source| db_error(&source))?;

    Ok(json_response(
        StatusCode::CREATED,
        json!({ "invitation_token": token }),
    ))
}

#[derive(Debug, Deserialize)]
struct RegisterBody {
    invitation_token: String,
    name: String,
}

/// `POST /api/auth/register`: claim an invitation token by picking a name.
/// A name that already exists claims that user; a free name claims the
/// token's own user row (the invited placeholder, or the admin's user 0 for
/// the bootstrap token).
async fn register(
    State(state): State<AppState>,
    Json(body): Json<RegisterBody>,
) -> Result<Response, Response> {
    let Ok(hash) = hash_from_b64(&body.invitation_token) else {
        return Ok(json_error(StatusCode::BAD_REQUEST, "malformed token"));
    };

    let now = unix_now();
    let mut tx = state.db.begin().await.map_err(|source| db_error(&source))?;

    let token = sqlx::query_as!(
        TokenRow,
        "SELECT user_id, expires FROM tokens
         WHERE token_hash = ? AND kind = 'invitation'",
        &hash[..]
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|source| db_error(&source))?;
    let Some(token) = token else {
        return Ok(json_error(
            StatusCode::NOT_FOUND,
            "unknown invitation token",
        ));
    };
    if token.expires.is_some_and(|expires| expires <= now) {
        return Ok(json_error(
            StatusCode::UNAUTHORIZED,
            "invitation token expired",
        ));
    }

    let claimed = sqlx::query_as!(UserIdRow, "SELECT id FROM users WHERE name = ?", body.name)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|source| db_error(&source))?;

    let user_id = if let Some(existing) = claimed {
        // Claim the existing user. The invited placeholder row becomes an
        // orphan; drop it in the same transaction, but never the admin,
        // a named user, or the claimed user itself. The token row goes
        // first so the foreign key does not hold the deletion back.
        sqlx::query!("DELETE FROM tokens WHERE token_hash = ?", &hash[..])
            .execute(&mut *tx)
            .await
            .map_err(|source| db_error(&source))?;
        sqlx::query!(
            "DELETE FROM users WHERE id = ? AND id != 0 AND id != ? AND name IS NULL",
            token.user_id,
            existing.id
        )
        .execute(&mut *tx)
        .await
        .map_err(|source| db_error(&source))?;
        existing.id
    } else {
        let updated = sqlx::query!(
            "UPDATE users SET name = ? WHERE id = ?",
            body.name,
            token.user_id
        )
        .execute(&mut *tx)
        .await
        .map_err(|source| {
            if source
                .as_database_error()
                .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
            {
                json_error(StatusCode::BAD_REQUEST, "user already exists")
            } else {
                db_error(&source)
            }
        })?;
        if updated.rows_affected() == 0 {
            return Ok(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "token user is gone",
            ));
        }
        sqlx::query!("DELETE FROM tokens WHERE token_hash = ?", &hash[..])
            .execute(&mut *tx)
            .await
            .map_err(|source| db_error(&source))?;
        token.user_id
    };

    let (session_token, session_hash) = generate_token();
    let expires = now.saturating_add(SESSION_LIFETIME_SECS);
    sqlx::query!(
        "INSERT INTO sessions (token_hash, user_id, expires) VALUES (?, ?, ?)",
        &session_hash[..],
        user_id,
        expires
    )
    .execute(&mut *tx)
    .await
    .map_err(|source| db_error(&source))?;
    tx.commit().await.map_err(|source| db_error(&source))?;

    Ok(set_cookie_response(&session_token))
}

#[derive(Debug, Deserialize)]
struct LoginBody {
    login_token: String,
}

/// `POST /api/auth/login`: trade a one-shot login token for a session.
async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginBody>,
) -> Result<Response, Response> {
    let Ok(hash) = hash_from_b64(&body.login_token) else {
        return Ok(json_error(StatusCode::BAD_REQUEST, "malformed token"));
    };

    let now = unix_now();
    let mut tx = state.db.begin().await.map_err(|source| db_error(&source))?;
    let token = sqlx::query_as!(
        TokenRow,
        "SELECT user_id, expires FROM tokens WHERE token_hash = ? AND kind = 'login'",
        &hash[..]
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|source| db_error(&source))?;
    let Some(token) = token else {
        return Ok(json_error(StatusCode::NOT_FOUND, "unknown login token"));
    };
    if token.expires.is_some_and(|expires| expires <= now) {
        return Ok(json_error(StatusCode::UNAUTHORIZED, "login token expired"));
    }

    sqlx::query!("DELETE FROM tokens WHERE token_hash = ?", &hash[..])
        .execute(&mut *tx)
        .await
        .map_err(|source| db_error(&source))?;
    let (session_token, session_hash) = generate_token();
    let expires = now.saturating_add(SESSION_LIFETIME_SECS);
    sqlx::query!(
        "INSERT INTO sessions (token_hash, user_id, expires) VALUES (?, ?, ?)",
        &session_hash[..],
        token.user_id,
        expires
    )
    .execute(&mut *tx)
    .await
    .map_err(|source| db_error(&source))?;
    tx.commit().await.map_err(|source| db_error(&source))?;

    Ok(set_cookie_response(&session_token))
}

/// `POST /api/auth/addDevice`: mint a 1-hour login token for the caller.
async fn add_device(
    State(state): State<AppState>,
    Extension(user): Extension<AuthedUser>,
) -> Result<Response, Response> {
    let (token, hash) = generate_token();
    let expires = unix_now().saturating_add(LOGIN_TOKEN_LIFETIME_SECS);
    sqlx::query!(
        r#"INSERT INTO tokens (token_hash, kind, user_id, expires)
           VALUES (?, 'login', ?, ?)"#,
        &hash[..],
        user.id,
        expires
    )
    .execute(&state.db)
    .await
    .map_err(|source| db_error(&source))?;
    Ok(json_response(
        StatusCode::CREATED,
        json!({ "login_token": token }),
    ))
}

/// `GET /api/auth/me`: who am I. A NULL name renders as the literal string
/// `"<null>"`, mc-runner parity wart.
async fn me(Extension(user): Extension<AuthedUser>) -> Response {
    let name = user.name.unwrap_or_else(|| String::from("<null>"));
    json_response(StatusCode::OK, json!({ "id": user.id, "name": name }))
}

/// `DELETE /api/auth/logout`: delete the current session row and clear the
/// cookie. The session is found by the pre-rotation hash from the request
/// extensions.
async fn logout(
    State(state): State<AppState>,
    Extension(user): Extension<AuthedUser>,
    Extension(SessionTokenHash(old_hash)): Extension<SessionTokenHash>,
) -> Result<Response, Response> {
    sqlx::query!(
        "DELETE FROM sessions WHERE token_hash = ? AND user_id = ?",
        &old_hash[..],
        user.id
    )
    .execute(&state.db)
    .await
    .map_err(|source| db_error(&source))?;

    let mut response = (StatusCode::OK, Json(json!({}))).into_response();
    if let Some(cookie) = clear_cookie_header() {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    Ok(response)
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|cookies| {
            cookies.split(';').find_map(|pair| {
                let (key, value) = pair.trim().split_once('=')?;
                (key == name).then_some(value)
            })
        })
}

fn cookie_header(token: &str, max_age_secs: i64) -> Option<HeaderValue> {
    HeaderValue::from_str(&format!(
        "auth={token}; {COOKIE_ATTRIBUTES}; Max-Age={max_age_secs}"
    ))
    .ok()
}

fn clear_cookie_header() -> Option<HeaderValue> {
    HeaderValue::from_str(&format!("auth=; {COOKIE_ATTRIBUTES}; Max-Age=0")).ok()
}

fn set_cookie_response(token: &str) -> Response {
    let Some(cookie) = cookie_header(token, SESSION_LIFETIME_SECS) else {
        return internal_error();
    };
    let mut response = StatusCode::CREATED.into_response();
    response.headers_mut().append(header::SET_COOKIE, cookie);
    response
}

fn json_response(status: StatusCode, body: serde_json::Value) -> Response {
    (status, Json(body)).into_response()
}

fn json_error(status: StatusCode, message: &str) -> Response {
    json_response(status, json!({ "error": message }))
}

fn db_error(source: &sqlx::Error) -> Response {
    error!("database error while handling an auth request: {source}");
    json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
}

fn internal_error() -> Response {
    json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with_cookie(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(value).unwrap_or_else(|err| panic!("static header: {err}")),
        );
        headers
    }

    #[test]
    fn cookie_value_finds_the_token() {
        let headers = headers_with_cookie("other=1; auth=abc_def-123; extra=3");
        assert_eq!(cookie_value(&headers, "auth"), Some("abc_def-123"));
    }

    #[test]
    fn cookie_value_handles_multiple_cookie_headers() {
        let mut headers = HeaderMap::new();
        headers.append(header::COOKIE, HeaderValue::from_static("a=1"));
        headers.append(header::COOKIE, HeaderValue::from_static("auth=xyz"));
        assert_eq!(cookie_value(&headers, "auth"), Some("xyz"));
        assert_eq!(cookie_value(&headers, "a"), Some("1"));
    }

    #[test]
    fn cookie_value_is_none_when_absent() {
        let headers = headers_with_cookie("other=1");
        assert_eq!(cookie_value(&headers, "auth"), None);
        assert_eq!(cookie_value(&HeaderMap::new(), "auth"), None);
    }

    #[test]
    fn cookie_headers_have_the_expected_attributes() {
        let set = cookie_header("tok", 60).unwrap_or_else(|| panic!("cookie header"));
        assert!(set.to_str().unwrap_or_default().starts_with("auth=tok; "));
        assert!(
            set.to_str()
                .unwrap_or_default()
                .contains("HttpOnly; SameSite=Lax; Secure; Max-Age=60")
        );
        let clear = clear_cookie_header().unwrap_or_else(|| panic!("clear header"));
        assert!(clear.to_str().unwrap_or_default().starts_with("auth=; "));
        assert!(clear.to_str().unwrap_or_default().contains("Max-Age=0"));
    }

    #[test]
    fn lifetime_constants_are_as_specified() {
        assert_eq!(SESSION_LIFETIME_SECS, 30 * 24 * 60 * 60);
        assert_eq!(INVITE_LIFETIME_SECS, 3 * 24 * 60 * 60);
        assert_eq!(LOGIN_TOKEN_LIFETIME_SECS, 60 * 60);
    }
}
