//! Auth endpoints and middleware: telegram login with an admin approval
//! queue, the OIDC admin login (see [`super::oidc`]), and sessions that
//! rotate and slide their expiry on every authenticated request. Error
//! bodies are small JSON; the frontend only reads the status.

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};
use serde_json::json;
use sqlx::SqlitePool;
use tracing::error;

use crate::clock::unix_now;
use crate::db::{ADMIN_MARKER_LIFETIME_SECS, PENDING_LIFETIME_SECS, SESSION_LIFETIME_SECS};
use crate::telegram;
use crate::tokens::generate_token;
use crate::tokens::hash_from_b64;
use crate::web::AppState;

/// Upper bound on queued registration requests, so a public vhost cannot
/// grow the table without bound.
pub const PENDING_QUEUE_CAP: i64 = 100;

/// Name of the cookie carrying the OIDC login state token.
pub const OIDC_STATE_COOKIE: &str = "oidc_login";

/// Name of the cookie marking a browser that completed an admin SSO login
/// before. The login page auto-redirects such a browser straight into the
/// provider, so regular users never see any admin surface. Logout clears
/// it; so it stays invisible unless the admin logs in again.
pub const WAS_ADMIN_COOKIE: &str = "was_admin";

/// Attributes shared by the set and clear session cookie; only the value
/// and Max-Age differ.
const COOKIE_ATTRIBUTES: &str = "Path=/api; HttpOnly; SameSite=Lax; Secure";

/// Build the auth routes under `/api/auth`.
pub fn auth_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/config", get(config))
        .route("/telegram", post(telegram_login))
        .route("/oidc/login", get(super::oidc::login))
        .route("/oidc/callback", get(super::oidc::callback))
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
pub struct AuthedUser {
    pub id: i64,
    pub name: Option<String>,
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

/// `GET /api/auth/config`: which login methods this runner offers. The
/// login page renders itself from this. `was_admin` says whether this
/// browser completed an admin SSO login before; only the login flow reads
/// it, and it exists precisely so the admin never sees a login page.
async fn config(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let was_admin = cookie_value(&headers, WAS_ADMIN_COOKIE).is_some();
    json_response(
        StatusCode::OK,
        json!({
            "bot_username": state.bot_username(),
            "oidc": state.oidc.is_some(),
            "was_admin": was_admin,
        }),
    )
}

/// `POST /api/auth/telegram`: trade a signed telegram login widget payload
/// for a session. Known accounts log in directly; unknown accounts land in
/// the approval queue; banned accounts are refused.
async fn telegram_login(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Response, Response> {
    struct AccountRow {
        id: i64,
        banned: bool,
    }
    if !state.telegram.login_configured() {
        return Ok(json_error(
            StatusCode::NOT_FOUND,
            "telegram login is not configured",
        ));
    }
    let Some(payload) = body.as_object() else {
        return Ok(json_error(
            StatusCode::BAD_REQUEST,
            "the login payload must be a JSON object",
        ));
    };
    let identity = telegram::verify_login_payload(payload, &state.telegram.token, unix_now())
        .map_err(|err| {
            let (status, message) = match err {
                telegram::LoginVerifyError::Stale => {
                    (StatusCode::BAD_REQUEST, "login payload expired, try again")
                }
                telegram::LoginVerifyError::Malformed
                | telegram::LoginVerifyError::BadSignature => {
                    (StatusCode::UNAUTHORIZED, "invalid login payload")
                }
            };
            json_error(status, message)
        })?;

    let account = sqlx::query_as!(
        AccountRow,
        r#"SELECT id, banned AS "banned: bool" FROM users WHERE telegram_id = ?"#,
        identity.telegram_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|source| db_error(&source))?;

    if let Some(account) = account {
        if account.banned {
            return Ok(json_error(StatusCode::FORBIDDEN, "this account is banned"));
        }
        return mint_session_response(&state.db, account.id).await;
    }

    // Unknown account: queue a registration request for the admin to
    // approve.
    queue_registration(&state, &identity).await
}

/// Queue an unknown account for admin approval. A second request while
/// already queued is a conflict, not a new queue entry.
async fn queue_registration(
    state: &AppState,
    identity: &telegram::LoginIdentity,
) -> Result<Response, Response> {
    struct PendingCount {
        count: i64,
    }
    let PendingCount { count } = sqlx::query_as!(
        PendingCount,
        r#"SELECT COUNT(*) AS "count: i64" FROM pending_users"#,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|source| db_error(&source))?;
    if count >= PENDING_QUEUE_CAP {
        return Ok(json_error(
            StatusCode::TOO_MANY_REQUESTS,
            "the registration queue is full, try again later",
        ));
    }

    let created = unix_now();
    let cutoff = created.saturating_sub(PENDING_LIFETIME_SECS);
    struct ExistingRow {
        created: i64,
    }
    let existing = sqlx::query_as!(
        ExistingRow,
        "SELECT created FROM pending_users WHERE telegram_id = ?",
        identity.telegram_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|source| db_error(&source))?;
    match existing {
        // A live request: a second one is a conflict, never a refresh.
        Some(row) if row.created > cutoff => {
            return Ok(json_error(
                StatusCode::CONFLICT,
                "a registration request for this account is already \
                 waiting for approval",
            ));
        }
        // An expired request the hourly sweep has not reached yet: it is
        // invisible to the admin and unapprovable, so replace it.
        Some(_) => {
            let refreshed = sqlx::query!(
                "UPDATE pending_users SET name = ?, username = ?, created = ?
                 WHERE telegram_id = ?",
                identity.name,
                identity.username,
                created,
                identity.telegram_id
            )
            .execute(&state.db)
            .await;
            if let Err(source) = refreshed {
                return Err(db_error(&source));
            }
        }
        None => {
            let inserted = sqlx::query!(
                "INSERT INTO pending_users (telegram_id, name, username, created)
                 VALUES (?, ?, ?, ?)",
                identity.telegram_id,
                identity.name,
                identity.username,
                created
            )
            .execute(&state.db)
            .await;
            if let Err(source) = inserted {
                if source
                    .as_database_error()
                    .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
                {
                    // Lost a race with a concurrent request; treat it as
                    // the conflict it is.
                    return Ok(json_error(
                        StatusCode::CONFLICT,
                        "a registration request for this account is already \
                         waiting for approval",
                    ));
                }
                return Err(db_error(&source));
            }
        }
    }

    Ok(json_response(
        StatusCode::ACCEPTED,
        json!({ "status": "pending" }),
    ))
}

/// Mint a fresh session row for `user_id` and return the `Set-Cookie`
/// header value, ready to append to any response.
pub async fn mint_session_cookie(db: &SqlitePool, user_id: i64) -> Result<HeaderValue, Response> {
    let (token, hash) = generate_token();
    let expires = unix_now().saturating_add(SESSION_LIFETIME_SECS);
    sqlx::query!(
        "INSERT INTO sessions (token_hash, user_id, expires) VALUES (?, ?, ?)",
        &hash[..],
        user_id,
        expires
    )
    .execute(db)
    .await
    .map_err(|source| db_error(&source))?;
    cookie_header(&token, SESSION_LIFETIME_SECS).ok_or_else(internal_error)
}

/// Mint a session and answer like the old registration endpoint: 201 with
/// the session cookie set.
async fn mint_session_response(db: &SqlitePool, user_id: i64) -> Result<Response, Response> {
    let cookie = mint_session_cookie(db, user_id).await?;
    let mut response = StatusCode::CREATED.into_response();
    response.headers_mut().append(header::SET_COOKIE, cookie);
    Ok(response)
}

/// `GET /api/auth/me`: who am I. A NULL name renders as the literal string
/// `"<null>"`, mc-runner parity wart. `is_admin` gates the admin surface of
/// the frontend; the check is the structural one.
async fn me(Extension(user): Extension<AuthedUser>) -> Response {
    let name = user.name.unwrap_or_else(|| String::from("<null>"));
    json_response(
        StatusCode::OK,
        json!({
            "id": user.id,
            "name": name,
            "is_admin": user.id == 0,
        }),
    )
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
    // Leaving admin mode means the browser stops auto-redirecting into the
    // SSO flow; the next login happens through the same page everyone sees.
    if let Some(cookie) = clear_was_admin_cookie() {
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

/// Set-Cookie value marking the browser as one that has seen a completed
/// admin SSO login.
pub fn was_admin_cookie() -> Option<HeaderValue> {
    HeaderValue::from_str(&format!(
        "{WAS_ADMIN_COOKIE}=1; {COOKIE_ATTRIBUTES}; \
         Max-Age={ADMIN_MARKER_LIFETIME_SECS}"
    ))
    .ok()
}

pub fn clear_was_admin_cookie() -> Option<HeaderValue> {
    HeaderValue::from_str(&format!(
        "{WAS_ADMIN_COOKIE}=; {COOKIE_ATTRIBUTES}; Max-Age=0"
    ))
    .ok()
}

fn clear_cookie_header() -> Option<HeaderValue> {
    HeaderValue::from_str(&format!("auth=; {COOKIE_ATTRIBUTES}; Max-Age=0")).ok()
}

fn json_response(status: StatusCode, body: serde_json::Value) -> Response {
    (status, Json(body)).into_response()
}

pub fn json_error(status: StatusCode, message: &str) -> Response {
    json_response(status, json!({ "error": message }))
}

pub fn db_error(source: &sqlx::Error) -> Response {
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
        assert_eq!(
            crate::db::PENDING_LIFETIME_SECS,
            60 * 60,
            "pending requests live one hour"
        );
        assert_eq!(
            crate::db::OIDC_STATE_LIFETIME_SECS,
            10 * 60,
            "in-flight oidc logins live ten minutes"
        );
    }
}
