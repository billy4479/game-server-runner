//! The OIDC admin login, hand-rolled like ff: authorization code with PKCE
//! S256, `client_secret_post` at the token endpoint, and identity claims
//! read from `/userinfo` with the opaque access token (the ID token is
//! never parsed). Exactly one identity is accepted: the one whose
//! `username` claim equals the configured admin username. In-flight logins
//! are tracked server-side: a state token lives in a browser cookie, its
//! hash in the database next to the matching PKCE verifier.

use std::sync::OnceLock;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::Client;
use serde::Deserialize;
use sha2::Digest;
use sha2::Sha256;
use std::collections::HashMap;
use tracing::error;

use crate::clock::unix_now;
use crate::db::OIDC_STATE_LIFETIME_SECS;
use crate::tokens::generate_token;
use crate::tokens::hash_from_b64;
use crate::web::AppState;
use crate::web::auth::{
    OIDC_STATE_COOKIE, db_error, json_error, mint_session_cookie, was_admin_cookie,
};

/// Total timeout for the provider round trips.
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(10);

/// The shared http client for provider calls, built once per process.
fn shared_client() -> Option<&'static Client> {
    static CLIENT: OnceLock<Option<Client>> = OnceLock::new();
    CLIENT
        .get_or_init(
            || match Client::builder().timeout(PROVIDER_TIMEOUT).build() {
                Ok(client) => Some(client),
                Err(source) => {
                    error!("could not build the oidc http client: {source}");
                    None
                }
            },
        )
        .as_ref()
}

/// `GET /api/auth/oidc/login`: start an admin login. Stores the PKCE
/// verifier under a fresh state token (cookie + database row), remembers
/// which in-site path brought the visitor here, and sends the browser to
/// the provider.
pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(start): Query<HashMap<String, String>>,
) -> Response {
    let Some(config) = state.oidc.clone() else {
        return json_error(StatusCode::NOT_FOUND, "oidc admin login is not configured");
    };
    let Some(callback) = callback_url(&headers) else {
        return login_error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not determine the callback address of this runner",
        );
    };
    let return_to = sanitized_return_to(start.get("return_to").map(String::as_str));

    let verifier = pkce_verifier();
    let challenge = pkce_challenge(&verifier);
    let (state_token, state_hash) = generate_token();
    let expires = unix_now().saturating_add(OIDC_STATE_LIFETIME_SECS);
    let inserted = sqlx::query!(
        "INSERT INTO oidc_logins (state_hash, verifier, return_to, expires)
         VALUES (?, ?, ?, ?)",
        &state_hash[..],
        verifier,
        return_to,
        expires
    )
    .execute(&state.db)
    .await;
    if let Err(source) = inserted {
        return db_error(&source);
    }

    let url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        config.authorize_url(),
        percent_encode(&config.client_id),
        percent_encode(&callback),
        percent_encode("openid profile email"),
        percent_encode(&state_token),
        percent_encode(&challenge),
    );

    let mut response = Redirect::to(&url).into_response();
    if let Some(cookie) = state_cookie(&state_token) {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

#[derive(Debug, Deserialize)]
struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// `GET /api/auth/oidc/callback`: finish an admin login. Exchanges the code
/// for tokens with the stored verifier, reads the identity from
/// `/userinfo`, and only then checks it against the configured admin.
pub async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let params = CallbackParams {
        code: params.get("code").cloned(),
        state: params.get("state").cloned(),
        error: params.get("error").cloned(),
    };
    let Some(config) = state.oidc.clone() else {
        return json_error(StatusCode::NOT_FOUND, "oidc admin login is not configured");
    };
    #[derive(Deserialize)]
    struct TokenJson {
        access_token: String,
    }
    if params.error.is_some() {
        // The provider bounced the user back with an error: denied,
        // cancelled, or broken. No reason to expose which.
        return login_error_page(
            StatusCode::FORBIDDEN,
            "the provider did not authorize this login",
        );
    }
    let Some(code) = params.code else {
        return login_error_page(
            StatusCode::FORBIDDEN,
            "the provider did not authorize this login",
        );
    };

    // The state token binds the browser to the login attempt. One-shot:
    // delete first, so a replayed callback never finds it again.
    struct LoginRow {
        verifier: String,
        return_to: String,
        expires: i64,
    }
    let Some(state_token) = cookie_value(&headers, OIDC_STATE_COOKIE) else {
        return login_error_page(
            StatusCode::BAD_REQUEST,
            "this login attempt has no state cookie; start again",
        );
    };
    if params.state.as_deref() != Some(state_token) {
        return login_error_page(
            StatusCode::BAD_REQUEST,
            "this login attempt does not match its state cookie; start again",
        );
    }
    let Ok(state_hash) = hash_from_b64(state_token) else {
        return login_error_page(
            StatusCode::BAD_REQUEST,
            "this login attempt has a malformed state cookie; start again",
        );
    };
    let row = sqlx::query_as!(
        LoginRow,
        "SELECT verifier, return_to, expires FROM oidc_logins WHERE state_hash = ?",
        &state_hash[..]
    )
    .fetch_optional(&state.db)
    .await;
    let row = match row {
        Ok(Some(row)) => row,
        Ok(None) => {
            return login_error_page(
                StatusCode::BAD_REQUEST,
                "unknown or already used login attempt; start again",
            );
        }
        Err(source) => return db_error(&source),
    };
    let deleted = sqlx::query!(
        "DELETE FROM oidc_logins WHERE state_hash = ?",
        &state_hash[..]
    )
    .execute(&state.db)
    .await;
    if let Err(source) = deleted {
        return db_error(&source);
    }
    if row.expires <= unix_now() {
        return login_error_page(
            StatusCode::BAD_REQUEST,
            "this login attempt expired; start again",
        );
    }

    // Complete the authorization code exchange.
    let Some(callback) = callback_url(&headers) else {
        return login_error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not determine the callback address of this runner",
        );
    };
    let Some(client) = shared_client() else {
        return login_error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the http client is unavailable",
        );
    };
    let token_response = client
        .post(config.token_url())
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", callback.as_str()),
            ("client_id", config.client_id.as_str()),
            ("client_secret", config.client_secret.as_str()),
            ("code_verifier", row.verifier.as_str()),
        ])
        .send()
        .await;
    let token_response = match token_response {
        Ok(response) => response,
        Err(source) => {
            error!("oidc token endpoint unreachable: {source}");
            return login_error_page(
                StatusCode::BAD_GATEWAY,
                "could not reach the login provider",
            );
        }
    };
    if !token_response.status().is_success() {
        error!(
            status = token_response.status().as_u16(),
            "oidc token exchange failed"
        );
        return login_error_page(
            StatusCode::BAD_GATEWAY,
            "the login provider rejected the token exchange",
        );
    }
    let token: TokenJson = match token_response.json().await {
        Ok(json) => json,
        Err(source) => {
            error!("oidc token response is not valid json: {source}");
            return login_error_page(
                StatusCode::BAD_GATEWAY,
                "the login provider returned a malformed token response",
            );
        }
    };

    // Identity claims come from /userinfo with the opaque access token.
    let userinfo = client
        .get(config.userinfo_url())
        .bearer_auth(&token.access_token)
        .send()
        .await;
    let userinfo = match userinfo {
        Ok(response) if response.status().is_success() => response,
        Ok(response) => {
            error!(
                status = response.status().as_u16(),
                "oidc userinfo endpoint refused the access token"
            );
            return login_error_page(
                StatusCode::BAD_GATEWAY,
                "the login provider rejected the access token",
            );
        }
        Err(source) => {
            error!("oidc userinfo endpoint unreachable: {source}");
            return login_error_page(
                StatusCode::BAD_GATEWAY,
                "could not reach the login provider",
            );
        }
    };
    let userinfo: serde_json::Value = match userinfo.json().await {
        Ok(json) => json,
        Err(source) => {
            error!("oidc userinfo response is not valid json: {source}");
            return login_error_page(
                StatusCode::BAD_GATEWAY,
                "the login provider returned a malformed userinfo response",
            );
        }
    };
    let username = userinfo
        .get("username")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();

    // Authorization is enforced here, not by the provider: any tailnet
    // member can authenticate at tsidp, but only the configured admin gets
    // an account.
    if username != config.admin_username {
        error!(
            claimed = username,
            "an authenticated identity tried to log in as the admin"
        );
        return login_error_page(
            StatusCode::FORBIDDEN,
            "this account is not the administrator of this runner",
        );
    }

    // Claim user 0: the name is cosmetic and only filled on the first login.
    let named = sqlx::query!(
        "UPDATE users SET name = COALESCE(name, ?) WHERE id = 0",
        username
    )
    .execute(&state.db)
    .await;
    if let Err(source) = named {
        return db_error(&source);
    }

    let cookie = match mint_session_cookie(&state.db, 0).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    let mut response = Redirect::to(&row.return_to).into_response();
    response.headers_mut().append(header::SET_COOKIE, cookie);
    // Remember this browser as an admin browser: the login page will
    // auto-redirect it into the provider next time, with no login screen.
    if let Some(marker) = was_admin_cookie() {
        response.headers_mut().append(header::SET_COOKIE, marker);
    }
    response
}

/// The post-login destination may only ever be an in-site path: anything
/// else (absolute urls, protocol-relative ones) falls back to the console.
fn sanitized_return_to(from: Option<&str>) -> String {
    match from {
        Some(path) if path.starts_with('/') && !path.starts_with("//") => String::from(path),
        _ => String::from("/"),
    }
}

/// Build the callback url the way nginx forwards the request: honor the
/// forwarded scheme, use the Host header verbatim.
fn callback_url(headers: &HeaderMap) -> Option<String> {
    let host = headers.get(header::HOST)?.to_str().ok()?;
    if host.is_empty() {
        return None;
    }
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("http");
    Some(format!("{scheme}://{host}/api/auth/oidc/callback"))
}

/// Cookie binding an in-flight login to the browser that started it.
fn state_cookie(state_token: &str) -> Option<axum::http::HeaderValue> {
    axum::http::HeaderValue::from_str(&format!(
        "{OIDC_STATE_COOKIE}={state_token}; Path=/api/auth/oidc; \
         HttpOnly; SameSite=Lax; Secure; Max-Age={OIDC_STATE_LIFETIME_SECS}"
    ))
    .ok()
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

/// 43-character PKCE code verifier: 32 random bytes, unpadded base64url.
fn pkce_verifier() -> String {
    let raw: [u8; 32] = rand::random();
    URL_SAFE_NO_PAD.encode(raw)
}

/// PKCE S256 challenge for a verifier.
fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Percent-encode a query parameter: everything outside the RFC 3986
/// unreserved set.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(byte));
            }
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                out.push('%');
                let high = HEX.get(usize::from(byte >> 4)).copied().unwrap_or(b'0');
                let low = HEX.get(usize::from(byte & 15)).copied().unwrap_or(b'0');
                out.push(char::from(high));
                out.push(char::from(low));
            }
        }
    }
    out
}

/// Styled error page for the browser-driven login flow, in place of the
/// JSON the API endpoints speak. The way out carries `?sso=skip`, which
/// tells the login page not to auto-redirect into the provider this time —
/// otherwise a failed login would loop straight back into itself.
fn login_error_page(status: StatusCode, message: &str) -> Response {
    let body = format!(
        "<!DOCTYPE html><html><head><title>game-server-runner</title></head>\
         <body style=\"font-family: system-ui, sans-serif; background: #111; \
         color: #eee; display: flex; align-items: center; justify-content: center; \
         height: 100vh; margin: 0;\"><div style=\"max-width: 28rem; text-align: center;\">\
         <h1>Login failed</h1><p>{message}</p>\
         <p><a href=\"/?sso=skip\" style=\"color: #7dd3fc;\">Back to the start page</a></p>\
         </div></body></html>"
    );
    (status, Html(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_matches_the_rfc_7636_test_vector() {
        // The A.4 example from RFC 7636: verifier and derived S256 challenge.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            pkce_challenge(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn verifier_is_valid_base64url_of_32_bytes() {
        let verifier = pkce_verifier();
        assert_eq!(verifier.len(), 43, "32 bytes, unpadded base64url");
        assert!(hash_roundtrip(&verifier), "verifier should decode");
    }

    fn hash_roundtrip(value: &str) -> bool {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as ENGINE;
        ENGINE.decode(value).is_ok_and(|raw| raw.len() == 32)
    }

    #[test]
    fn percent_encode_leaves_unreserved_bytes_alone() {
        assert_eq!(percent_encode("abc-DEF_1.~"), "abc-DEF_1.~");
        assert_eq!(
            percent_encode("https://host.example/api/auth/oidc/callback"),
            "https%3A%2F%2Fhost.example%2Fapi%2Fauth%2Foidc%2Fcallback"
        );
        assert_eq!(percent_encode("a b"), "a%20b");
        assert_eq!(percent_encode(""), "");
    }

    #[test]
    fn return_to_only_accepts_in_site_paths() {
        assert_eq!(sanitized_return_to(Some("/admin")), "/admin");
        assert_eq!(
            sanitized_return_to(Some("/admin?next=/x")),
            "/admin?next=/x"
        );
        // Anything that could leave the site falls back to the console.
        assert_eq!(sanitized_return_to(Some("//evil.example")), "/");
        assert_eq!(sanitized_return_to(Some("https://evil.example")), "/");
        assert_eq!(sanitized_return_to(Some("admin")), "/");
        assert_eq!(sanitized_return_to(None), "/");
    }

    #[test]
    fn callback_url_uses_host_and_forwarded_proto() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::HOST,
            axum::http::HeaderValue::from_static("mc.example.com"),
        );
        assert_eq!(
            callback_url(&headers).as_deref(),
            Some("http://mc.example.com/api/auth/oidc/callback")
        );
        headers.insert(
            "x-forwarded-proto",
            axum::http::HeaderValue::from_static("https"),
        );
        assert_eq!(
            callback_url(&headers).as_deref(),
            Some("https://mc.example.com/api/auth/oidc/callback")
        );
        let empty = HeaderMap::new();
        assert_eq!(callback_url(&empty), None);
    }
}
