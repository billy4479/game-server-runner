//! HTTP routes: the status API, auth, the admin surface, the websocket
//! feed, and the frontend.

mod admin;
mod auth;
mod frontend;
mod oidc;
mod ws;

use std::sync::Arc;

use axum::Router;
use axum::middleware;
use axum::routing::get;
use sqlx::SqlitePool;

use crate::config::{OidcConfig, TelegramConfig};
use crate::server::Runner;

/// Shared state for every route: the runner, the database pool, and the
/// login configurations.
#[derive(Clone)]
pub struct AppState {
    /// The game server runner.
    pub runner: Arc<Runner>,
    /// Database pool for auth and sessions.
    pub db: SqlitePool,
    /// Telegram settings; the notification bot doubles as the login
    /// provider.
    pub telegram: TelegramConfig,
    /// Admin login provider, `None` when unconfigured.
    pub oidc: Option<OidcConfig>,
}

impl AppState {
    /// The bot username exposed to the login widget, when login can work:
    /// it needs both the public username and the token to verify with.
    #[must_use]
    pub fn bot_username(&self) -> Option<&str> {
        if !self.telegram.login_configured() {
            return None;
        }
        let username = self.telegram.username.trim();
        (!username.is_empty()).then_some(username)
    }
}

/// Build the application router. `/api/ping` is public; the auth, admin and
/// websocket routes sit behind the auth middleware (admin routes additionally
/// behind the admin middleware).
pub fn router(state: AppState) -> Router {
    let auth = middleware::from_fn_with_state(state.clone(), auth::auth_middleware);
    Router::new()
        .route("/api/ping", get(ping))
        .nest("/api/auth", auth::auth_routes(state.clone()))
        .nest("/api/admin", admin::admin_routes(state.clone()))
        .route("/api/ws", get(ws::ws_handler).route_layer(auth))
        .fallback(frontend::fallback)
        .with_state(state)
}

async fn ping() -> &'static str {
    "pong"
}
