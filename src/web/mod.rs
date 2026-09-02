//! HTTP routes: the status API, auth, the websocket feed, and the frontend.

mod auth;
mod ws;

use std::sync::Arc;

use axum::Router;
use axum::middleware;
use axum::routing::get;
use sqlx::SqlitePool;

use crate::server::Runner;

/// Shared state for every route: the runner plus the database pool.
#[derive(Clone)]
pub struct AppState {
    /// The game server runner.
    pub runner: Arc<Runner>,
    /// Database pool for auth and sessions.
    pub db: SqlitePool,
}

/// Build the application router. `/api/ping` is public; the auth and
/// websocket routes sit behind the auth middleware.
pub fn router(state: AppState) -> Router {
    let auth = middleware::from_fn_with_state(state.clone(), auth::auth_middleware);
    Router::new()
        .route("/api/ping", get(ping))
        .nest("/api/auth", auth::auth_routes(state.clone()))
        .route("/api/ws", get(ws::ws_handler).route_layer(auth))
        .with_state(state)
}

async fn ping() -> &'static str {
    "pong"
}
