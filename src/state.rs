//! Types shared with websocket clients: the server state snapshot and the
//! `{type, data}` feed messages.

use serde::Serialize;

/// Snapshot of the server status, serialized with the exact JSON keys that
/// mc-runner uses, warts included (`bot_tag` is always empty).
#[derive(Debug, Clone, Serialize)]
pub struct ServerState {
    /// Version of this runner binary.
    pub version: String,
    /// Address players use to connect to the game server.
    pub connect_url: String,
    /// Name of the server from `server.toml`.
    pub server_name: String,
    /// Whether the game server process is currently up.
    pub is_running: bool,
    /// Names of online players, sorted.
    pub online_players: Vec<String>,
    /// Unix seconds of the scheduled auto stop, `i64::MAX` when none is
    /// scheduled.
    pub auto_stop_time: i64,
    /// Always empty; kept for shape parity with mc-runner.
    pub bot_tag: String,
}

/// One websocket feed message, serialized as `{"type": ..., "data": ...}`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "lowercase")]
pub enum FeedMessage {
    /// A full state snapshot.
    State(ServerState),
    /// One output line of the game server, or the whole history on connect.
    Chat(String),
}
