//! Configuration loading and validation.
//!
//! Two files are read: the global `config.toml`, whose path comes from the
//! `CONFIG_PATH` environment variable (default `config.toml`, no dotenv
//! support), and one `server.toml` inside the configured server directory.
//! All validation, including player regex compilation and the whole stop
//! configuration, happens at startup so bad configs fail fast.

use std::path::{Path, PathBuf};
use std::time::Duration;

use regex::Regex;
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::signals::GracefulSignal;

/// File name of the per-server config, expected directly inside `server_dir`.
pub const SERVER_CONFIG_FILE: &str = "server.toml";

/// Default join pattern, shaped after real vanilla/Paper console output where
/// the timestamp prefix is three space-free tokens. The `regex` crate
/// supports no lookarounds or backreferences, so overrides must stay within
/// its syntax.
pub const DEFAULT_JOIN_REGEX: &str = r"^\S+ \S+ \S+ (?P<player>\S+) joined the game";

/// Default leave pattern, same shape as [`DEFAULT_JOIN_REGEX`].
pub const DEFAULT_LEAVE_REGEX: &str = r"^\S+ \S+ \S+ (?P<player>\S+) left the game";

/// Grace period used when `grace_period` is not set in `server.toml`.
const DEFAULT_GRACE_PERIOD: Duration = Duration::from_secs(10);

/// Errors that can occur while loading or validating configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The config file could not be read.
    #[error("could not read {path}: {source}")]
    Read {
        /// File that was being read.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The config file is not valid TOML or a field has the wrong type.
    #[error("could not parse {path}: {source}")]
    Parse {
        /// File that was being parsed.
        path: PathBuf,
        /// Underlying TOML error.
        #[source]
        source: toml::de::Error,
    },
    /// The config parsed fine but is semantically invalid.
    #[error("{0}")]
    Invalid(String),
}

/// Global configuration from `config.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Path of the `SQLite` database file. Unused until M2 but parsed now.
    #[serde(default = "default_db_path")]
    pub db_path: String,
    /// TCP port the web server listens on.
    #[serde(default = "default_port")]
    pub port: u16,
    /// Address players use to connect to the game server.
    #[serde(default = "default_connect_url")]
    pub connect_url: String,
    /// Directory the game server runs in; also holds `server.toml`.
    #[serde(default = "default_server_dir")]
    pub server_dir: String,
    /// Minutes an empty server waits before it is stopped automatically.
    #[serde(default = "default_minutes_before_stop")]
    pub minutes_before_stop: u64,
    /// Log level: `debug`, `info`, `warn`, `error`, `err` or `disabled`.
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Whether restic backups run after a clean server exit (used in M4).
    #[serde(default)]
    pub restic_enable: bool,
    /// Path of the restic binary (used in M4).
    #[serde(default = "default_restic_path")]
    pub restic_path: String,
    /// Restic repository location (used in M4).
    #[serde(default)]
    pub restic_repo: String,
    /// Telegram settings (used in M4).
    #[serde(default)]
    pub telegram: TelegramConfig,
}

/// Telegram settings: the notification bot doubles as the login provider.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TelegramConfig {
    /// Bot token.
    #[serde(default)]
    pub token: String,
    /// Bot username without the leading `@`; the login widget needs the
    /// public name to embed itself.
    #[serde(default)]
    pub username: String,
    /// Semicolon-separated list of chat ids.
    #[serde(default)]
    pub chat_ids: String,
}

impl TelegramConfig {
    /// Whether a token is configured; lets logs reference the section
    /// without printing the secret.
    #[must_use]
    pub const fn token_configured(&self) -> bool {
        !self.token.is_empty()
    }

    /// Configured chat ids: the `chat_ids` string split on `;`, each entry
    /// trimmed, empty entries skipped.
    pub fn chat_ids(&self) -> impl Iterator<Item = &str> {
        self.chat_ids
            .split(';')
            .map(str::trim)
            .filter(|id| !id.is_empty())
    }

    /// Number of configured chat ids.
    #[must_use]
    pub fn chat_id_count(&self) -> usize {
        self.chat_ids().count()
    }

    /// Whether telegram login can work: it needs the token to verify widget
    /// payloads with and the public bot username for the widget embed.
    #[must_use]
    pub fn login_configured(&self) -> bool {
        self.token_configured() && !self.username.trim().is_empty()
    }
}

/// Admin login against the tailnet OIDC provider, configured entirely
/// through the environment (sops-rendered in deployment). The four settings
/// are accepted only as a complete set: anything in between fails the
/// startup, so a half-rendered secret template can never silently disable
/// the admin login or widen it.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// Issuer base URL, without a trailing slash.
    pub issuer: String,
    /// OAuth client id.
    pub client_id: String,
    /// OAuth client secret.
    pub client_secret: String,
    /// The only identity accepted as the admin: the `username` claim must
    /// equal this value.
    pub admin_username: String,
}

impl OidcConfig {
    /// Read the configuration from the environment.
    ///
    /// # Errors
    /// Returns [`ConfigError::Invalid`] when some but not all of the four
    /// variables are set.
    pub fn from_env() -> Result<Option<Self>, ConfigError> {
        let read = |key: &str| {
            std::env::var(key)
                .ok()
                .filter(|value| !value.trim().is_empty())
        };
        Self::from_values(
            read("OIDC_ISSUER"),
            read("OIDC_CLIENT_ID"),
            read("OIDC_CLIENT_SECRET"),
            read("ADMIN_USERNAME"),
        )
    }

    /// Validate the four settings as a unit: none set means the admin login
    /// is disabled, all set means it is enabled, anything else is an error.
    ///
    /// # Errors
    /// Returns [`ConfigError::Invalid`] when some but not all values are
    /// present.
    pub fn from_values(
        issuer: Option<String>,
        client_id: Option<String>,
        client_secret: Option<String>,
        admin_username: Option<String>,
    ) -> Result<Option<Self>, ConfigError> {
        match (issuer, client_id, client_secret, admin_username) {
            (None, None, None, None) => Ok(None),
            (Some(issuer), Some(client_id), Some(client_secret), Some(admin_username)) => {
                let issuer = issuer.trim_end_matches('/').to_string();
                Ok(Some(Self {
                    issuer,
                    client_id,
                    client_secret,
                    admin_username,
                }))
            }
            _ => Err(ConfigError::Invalid(String::from(
                "OIDC admin login is half configured: set OIDC_ISSUER, OIDC_CLIENT_ID, \
                 OIDC_CLIENT_SECRET and ADMIN_USERNAME together, or none of them",
            ))),
        }
    }

    /// The provider's authorization endpoint, per the tsidp endpoint layout.
    #[must_use]
    pub fn authorize_url(&self) -> String {
        format!("{}/authorize", self.issuer)
    }

    /// The provider's token endpoint.
    #[must_use]
    pub fn token_url(&self) -> String {
        format!("{}/token", self.issuer)
    }

    /// The provider's userinfo endpoint; identity claims are read from here
    /// with the opaque access token, never from the ID token.
    #[must_use]
    pub fn userinfo_url(&self) -> String {
        format!("{}/userinfo", self.issuer)
    }
}

fn default_db_path() -> String {
    "game-server-runner.db".to_string()
}

const fn default_port() -> u16 {
    4479
}

fn default_connect_url() -> String {
    "localhost:25565".to_string()
}

fn default_server_dir() -> String {
    ".".to_string()
}

const fn default_minutes_before_stop() -> u64 {
    1
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_restic_path() -> String {
    "restic".to_string()
}

/// Load the global configuration from the given path.
///
/// # Errors
/// Returns [`ConfigError::Read`] if the file cannot be read and
/// [`ConfigError::Parse`] if it is not valid TOML.
pub fn load_global_config(path: &Path) -> Result<Config, ConfigError> {
    let source = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    global_config_from_str(&source, path)
}

/// Parse and validate global configuration from a TOML string.
///
/// # Errors
/// Returns [`ConfigError::Parse`] if the input is not valid TOML.
pub fn global_config_from_str(source: &str, path: &Path) -> Result<Config, ConfigError> {
    parse_toml(source, path)
}

/// Load and validate the per-server configuration from `server_dir`.
///
/// # Errors
/// Returns [`ConfigError::Read`] if `server.toml` cannot be read,
/// [`ConfigError::Parse`] if it is not valid TOML and
/// [`ConfigError::Invalid`] if validation fails (bad regexes, bad stop
/// configuration, and so on).
pub fn load_server_config(server_dir: &Path) -> Result<ServerConfig, ConfigError> {
    let path = server_dir.join(SERVER_CONFIG_FILE);
    let source = std::fs::read_to_string(&path).map_err(|source| ConfigError::Read {
        path: path.clone(),
        source,
    })?;
    server_config_from_str(&source, &path)
}

/// Parse and validate a per-server configuration from a TOML string.
///
/// # Errors
/// See [`load_server_config`].
pub fn server_config_from_str(source: &str, path: &Path) -> Result<ServerConfig, ConfigError> {
    let raw: RawServerConfig = parse_toml(source, path)?;
    validate_server_config(raw)
}

fn parse_toml<T: DeserializeOwned>(source: &str, path: &Path) -> Result<T, ConfigError> {
    toml::from_str(source).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

fn validate_server_config(raw: RawServerConfig) -> Result<ServerConfig, ConfigError> {
    let players = PlayerRegexes::new(
        raw.players.join_regex.as_deref(),
        raw.players.leave_regex.as_deref(),
    )?;
    let stop = validate_stop(raw.stop)?;
    Ok(ServerConfig {
        server_name: raw.server_name,
        command: raw.command,
        args: raw.args,
        players,
        stop,
    })
}

/// Raw `[stop]` table as written in `server.toml`, before validation.
#[derive(Debug, Default, Deserialize)]
struct RawStopConfig {
    #[serde(default)]
    mode: StopMode,
    payload: Option<String>,
    #[serde(default, deserialize_with = "deserialize_grace_period")]
    grace_period: Option<Duration>,
}

/// How the runner asks the server to stop.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StopMode {
    /// Send a signal to the process.
    #[default]
    Signal,
    /// Write a command line to the process stdin.
    Stdin,
}

/// Serde helper: parse a duration string like `"10s"`, `"0.5s"` or `"250ms"`.
///
/// The syntax matches the std `Duration` parser: an optional `+`, a decimal
/// number and a unit of `ns`, `us`, `ms` or `s`. Composite units like `"1m"`
/// are not accepted, same as std.
///
/// # Errors
/// Returns a serde error describing why the input is not a valid duration.
fn deserialize_grace_period<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    parse_duration(&raw)
        .map(Some)
        .map_err(serde::de::Error::custom)
}

fn parse_duration(raw: &str) -> Result<Duration, String> {
    let invalid = |reason: &str| format!("invalid duration {raw:?}: {reason}");
    let body = raw.strip_prefix('+').unwrap_or(raw);
    let split = body
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .ok_or_else(|| invalid("time unit needed, for example 10s"))?;
    let (number, unit) = body.split_at(split);

    let (whole_raw, frac_raw) = match number.split_once('.') {
        Some((whole, frac)) => (whole, Some(frac)),
        None => (number, None),
    };
    let fraction_empty = frac_raw.is_none_or(str::is_empty);
    if whole_raw.is_empty() && fraction_empty {
        return Err(invalid("expected a number followed by a unit"));
    }
    if let Some(frac) = frac_raw
        && !frac.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid("the number is malformed"));
    }

    let seconds: u64 = if whole_raw.is_empty() {
        0
    } else {
        whole_raw
            .parse()
            .map_err(|source| invalid(&format!("the number is malformed: {source}")))?
    };
    // The fraction is truncated to nanosecond precision like std does.
    let fraction_scaled: u64 = match frac_raw {
        Some(frac) if !frac.is_empty() => {
            let nine_digits: String = frac.chars().take(9).collect();
            format!("{nine_digits:0<9}")
                .parse()
                .map_err(|source| invalid(&format!("the number is malformed: {source}")))?
        }
        _ => 0,
    };

    let unit_nanos: u64 = match unit {
        "ns" => 1,
        "us" | "µs" => 1_000,
        "ms" => 1_000_000,
        "s" => 1_000_000_000,
        _ => return Err(invalid(&format!("unknown time unit {unit:?}"))),
    };
    let total_nanos = seconds
        .checked_mul(unit_nanos)
        .and_then(|value| {
            value.checked_add(fraction_scaled.saturating_mul(unit_nanos) / 1_000_000_000)
        })
        .ok_or_else(|| invalid("the value is out of range"))?;
    Ok(Duration::from_nanos(total_nanos))
}

/// Validate the `[stop]` table into a ready-to-use stop configuration.
///
/// # Errors
/// Returns [`ConfigError::Invalid`] for signal payloads outside the
/// whitelist, `stdin` mode without a payload, or any error surfaced by the
/// grace period deserializer.
fn validate_stop(raw: RawStopConfig) -> Result<StopSettings, ConfigError> {
    let grace_period = raw.grace_period.unwrap_or(DEFAULT_GRACE_PERIOD);
    let payload = match raw.mode {
        StopMode::Signal => {
            let signal = match raw.payload.as_deref() {
                Some(name) => GracefulSignal::parse(name).map_err(ConfigError::Invalid)?,
                None => GracefulSignal::Term,
            };
            StopPayload::Signal(signal)
        }
        StopMode::Stdin => {
            let Some(mut line) = raw.payload else {
                return Err(ConfigError::Invalid(
                    "stop mode is \"stdin\" but no payload is configured; set \
                     [stop] payload to the command line to write to the server's stdin"
                        .to_string(),
                ));
            };
            if !line.ends_with('\n') {
                line.push('\n');
            }
            StopPayload::Stdin(line)
        }
    };
    Ok(StopSettings {
        payload,
        grace_period,
    })
}

/// Compiled player join/leave regexes.
#[derive(Debug, Clone)]
pub struct PlayerRegexes {
    /// Matches join lines, captures the player in the `player` group.
    pub join: Regex,
    /// Matches leave lines, captures the player in the `player` group.
    pub leave: Regex,
}

impl PlayerRegexes {
    /// Compile the join and leave regexes, falling back to the vanilla/Paper
    /// shaped defaults when not overridden.
    ///
    /// # Errors
    /// Returns [`ConfigError::Invalid`] if a pattern does not compile or is
    /// missing the required `(?P<player>...)` named group.
    pub fn new(join: Option<&str>, leave: Option<&str>) -> Result<Self, ConfigError> {
        Ok(Self {
            join: compile_player_regex(join.unwrap_or(DEFAULT_JOIN_REGEX), "join_regex")?,
            leave: compile_player_regex(leave.unwrap_or(DEFAULT_LEAVE_REGEX), "leave_regex")?,
        })
    }
}

fn compile_player_regex(pattern: &str, field: &str) -> Result<Regex, ConfigError> {
    let regex = Regex::new(pattern).map_err(|source| {
        ConfigError::Invalid(format!("{field}: invalid regex {pattern:?}: {source}"))
    })?;
    if !regex.capture_names().flatten().any(|name| name == "player") {
        return Err(ConfigError::Invalid(format!(
            "{field}: pattern {pattern:?} is missing the required named group \
             (?P<player>...)"
        )));
    }
    Ok(regex)
}

/// Per-server configuration from `server.toml`, fully validated.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Human readable server name.
    pub server_name: String,
    /// Executable to spawn.
    pub command: String,
    /// Command line arguments.
    pub args: Vec<String>,
    /// Compiled player regexes.
    pub players: PlayerRegexes,
    /// Validated stop configuration.
    pub stop: StopSettings,
}

/// What the graceful stop action actually does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopPayload {
    /// Send this signal to the process.
    Signal(GracefulSignal),
    /// Write this line, newline included, to the process stdin.
    Stdin(String),
}

/// Validated stop configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopSettings {
    /// The graceful stop action.
    pub payload: StopPayload,
    /// How long to wait after the graceful action before `SIGKILL`.
    pub grace_period: Duration,
}

/// Raw `[players]` table as written in `server.toml`.
#[derive(Debug, Default, Deserialize)]
struct RawPlayersConfig {
    join_regex: Option<String>,
    leave_regex: Option<String>,
}

/// Raw `server.toml` before validation.
#[derive(Debug, Deserialize)]
struct RawServerConfig {
    server_name: String,
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    players: RawPlayersConfig,
    #[serde(default)]
    stop: RawStopConfig,
}

/// Map the configured log level onto a tracing filter. `info` and any
/// unknown value fall back to `INFO`, mirroring mc-runner.
#[must_use]
pub fn log_level_filter(level: &str) -> tracing::level_filters::LevelFilter {
    use tracing::level_filters::LevelFilter;
    match level {
        "debug" => LevelFilter::DEBUG,
        "warn" => LevelFilter::WARN,
        "error" | "err" => LevelFilter::ERROR,
        "disabled" => LevelFilter::OFF,
        _ => LevelFilter::INFO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse_server(source: &str) -> Result<ServerConfig, ConfigError> {
        server_config_from_str(source, Path::new("server.toml"))
    }

    fn minimal_server() -> String {
        String::from("server_name = \"test\"\ncommand = \"true\"\n")
    }

    #[test]
    fn global_config_defaults_apply() {
        let config = global_config_from_str("", Path::new("config.toml"))
            .unwrap_or_else(|err| panic!("empty config should parse: {err}"));
        assert_eq!(config.db_path, "game-server-runner.db", "db path default");
        assert_eq!(config.port, 4479, "port default");
        assert_eq!(config.connect_url, "localhost:25565", "connect url default");
        assert_eq!(config.server_dir, ".", "server dir default");
        assert_eq!(config.minutes_before_stop, 1, "minutes default");
        assert_eq!(config.log_level, "info", "log level default");
        assert!(!config.restic_enable, "restic disabled by default");
        assert_eq!(config.restic_path, "restic", "restic path default");
        assert_eq!(config.restic_repo, "", "restic repo default");
        assert_eq!(config.telegram.token, "", "telegram token default");
        assert_eq!(config.telegram.username, "", "telegram username default");
        assert_eq!(config.telegram.chat_ids, "", "telegram chat ids default");
    }

    #[test]
    fn global_config_parses_all_fields() {
        let source = r"
db_path = '/tmp/db.sqlite'
port = 1234
connect_url = 'example.com:25565'
server_dir = '/srv/mc'
minutes_before_stop = 7
log_level = 'debug'
restic_enable = true
restic_path = '/usr/bin/restic'
restic_repo = '/backups/repo'

[telegram]
token = 'tok'
username = 'mybot'
chat_ids = '1;2;3'
";
        let config = global_config_from_str(source, Path::new("config.toml"))
            .unwrap_or_else(|err| panic!("config should parse: {err}"));
        assert_eq!(config.db_path, "/tmp/db.sqlite");
        assert_eq!(config.port, 1234);
        assert_eq!(config.connect_url, "example.com:25565");
        assert_eq!(config.server_dir, "/srv/mc");
        assert_eq!(config.minutes_before_stop, 7);
        assert_eq!(config.log_level, "debug");
        assert!(config.restic_enable);
        assert_eq!(config.restic_path, "/usr/bin/restic");
        assert_eq!(config.restic_repo, "/backups/repo");
        assert_eq!(config.telegram.token, "tok");
        assert_eq!(config.telegram.username, "mybot");
        assert_eq!(config.telegram.chat_ids, "1;2;3");
    }

    #[test]
    fn log_level_mapping() {
        use tracing::level_filters::LevelFilter;
        let cases = [
            ("debug", LevelFilter::DEBUG),
            ("info", LevelFilter::INFO),
            ("warn", LevelFilter::WARN),
            ("error", LevelFilter::ERROR),
            ("err", LevelFilter::ERROR),
            ("disabled", LevelFilter::OFF),
            ("bogus", LevelFilter::INFO),
        ];
        for (input, expected) in cases {
            assert_eq!(
                log_level_filter(input),
                expected,
                "mapping log level {input:?}"
            );
        }
    }

    #[test]
    fn stop_defaults_when_absent() {
        let config = parse_server(&minimal_server())
            .unwrap_or_else(|err| panic!("minimal config should parse: {err}"));
        assert_eq!(
            config.stop.payload,
            StopPayload::Signal(GracefulSignal::Term),
            "default stop should be SIGTERM"
        );
        assert_eq!(
            config.stop.grace_period,
            Duration::from_secs(10),
            "default grace period"
        );
    }

    #[test]
    fn signal_names_accepted_with_and_without_prefix() {
        let cases = [
            ("TERM", GracefulSignal::Term),
            ("term", GracefulSignal::Term),
            ("SIGTERM", GracefulSignal::Term),
            ("sigterm", GracefulSignal::Term),
            ("SigTerm", GracefulSignal::Term),
            ("INT", GracefulSignal::Int),
            ("SIGINT", GracefulSignal::Int),
            ("sIgInT", GracefulSignal::Int),
            ("HUP", GracefulSignal::Hup),
            ("SIGHUP", GracefulSignal::Hup),
            ("QUIT", GracefulSignal::Quit),
            ("SIGQUIT", GracefulSignal::Quit),
            ("sIGqUIt", GracefulSignal::Quit),
        ];
        for (name, expected) in cases {
            let source = format!("{}\n[stop]\npayload = \"{name}\"\n", minimal_server());
            let config = parse_server(&source)
                .unwrap_or_else(|err| panic!("signal {name} should be accepted: {err}"));
            assert_eq!(
                config.stop.payload,
                StopPayload::Signal(expected),
                "signal {name} should map to {expected:?}"
            );
        }
    }

    #[test]
    fn uncatchable_signals_are_rejected() {
        for name in ["KILL", "kill", "SIGKILL", "Kill", "STOP", "stop", "SIGSTOP"] {
            let source = format!("{}\n[stop]\npayload = \"{name}\"\n", minimal_server());
            let err = parse_server(&source)
                .err()
                .unwrap_or_else(|| panic!("signal {name} should have been rejected"));
            assert!(
                err.to_string().contains("cannot be caught"),
                "error for {name} should say it cannot be caught: {err}"
            );
        }
    }

    #[test]
    fn unknown_signal_is_rejected() {
        let source = format!("{}\n[stop]\npayload = \"SIGUSR1\"\n", minimal_server());
        let err = parse_server(&source)
            .err()
            .unwrap_or_else(|| panic!("unknown signal should have been rejected"));
        let message = err.to_string();
        assert!(
            message.contains("unknown stop signal"),
            "error should say the signal is unknown: {message}"
        );
        assert!(
            message.contains("TERM, INT, HUP, QUIT"),
            "error should list the allowed signals: {message}"
        );
    }

    #[test]
    fn stdin_payload_gets_newline_appended() {
        // The TOML string needs an escaped newline, written here as `\\n`.
        for (payload, expected) in [("stop", "stop\n"), ("stop\\n", "stop\n")] {
            let source = format!(
                "{}\n[stop]\nmode = \"stdin\"\npayload = \"{payload}\"\n",
                minimal_server()
            );
            let config = parse_server(&source).unwrap_or_else(|err| {
                panic!("stdin payload {payload:?} should be accepted: {err}")
            });
            assert_eq!(
                config.stop.payload,
                StopPayload::Stdin(expected.to_string()),
                "stdin payload {payload:?} should become {expected:?}"
            );
        }
    }

    #[test]
    fn stdin_mode_requires_payload() {
        let source = format!("{}\n[stop]\nmode = \"stdin\"\n", minimal_server());
        let err = parse_server(&source)
            .err()
            .unwrap_or_else(|| panic!("stdin mode without payload should be rejected"));
        let message = err.to_string();
        assert!(
            message.contains("stdin") && message.contains("payload"),
            "error should mention stdin and the payload: {message}"
        );
    }

    #[test]
    fn grace_period_parsing() {
        for (value, expected) in [
            ("1s", Duration::from_secs(1)),
            ("2s", Duration::from_secs(2)),
            ("0.5s", Duration::from_millis(500)),
            ("250ms", Duration::from_millis(250)),
        ] {
            let source = format!("{}\n[stop]\ngrace_period = \"{value}\"\n", minimal_server());
            let config = parse_server(&source)
                .unwrap_or_else(|err| panic!("grace period {value} should parse: {err}"));
            assert_eq!(config.stop.grace_period, expected, "grace period {value}");
        }
        for value in ["10", "abc", "1m", ""] {
            let source = format!("{}\n[stop]\ngrace_period = \"{value}\"\n", minimal_server());
            let err = parse_server(&source)
                .err()
                .unwrap_or_else(|| panic!("grace period {value:?} should be rejected"));
            assert!(
                err.to_string().contains("grace_period"),
                "error should mention grace_period: {err}"
            );
        }
    }

    #[test]
    fn player_regexes_default_to_vanilla_patterns() {
        let config = parse_server(&minimal_server())
            .unwrap_or_else(|err| panic!("minimal config should parse: {err}"));
        let line = "[12:34:56] [Server thread/INFO]: alice joined the game";
        let captured = config
            .players
            .join
            .captures(line)
            .and_then(|c| c.name("player"))
            .map(|m| m.as_str().to_string());
        assert_eq!(captured, Some("alice".to_string()), "default join regex");
    }

    #[test]
    fn player_regex_overrides_are_used() {
        let source = format!(
            "{}\n[players]\njoin_regex = '^(?P<player>\\S+) joined'\nleave_regex = '^(?P<player>\\S+) left'\n",
            minimal_server()
        );
        let config = parse_server(&source)
            .unwrap_or_else(|err| panic!("override config should parse: {err}"));
        let captured = config
            .players
            .leave
            .captures("bob left")
            .and_then(|c| c.name("player"))
            .map(|m| m.as_str().to_string());
        assert_eq!(captured, Some("bob".to_string()), "override leave regex");
    }

    #[test]
    fn player_regex_requires_named_group() {
        let source = format!(
            "{}\n[players]\njoin_regex = '^(\\S+) joined the game'\n",
            minimal_server()
        );
        let err = parse_server(&source)
            .err()
            .unwrap_or_else(|| panic!("pattern without named group should be rejected"));
        let message = err.to_string();
        assert!(
            message.contains("join_regex") && message.contains("(?P<player>...)"),
            "error should name the field and the missing group: {message}"
        );
    }

    #[test]
    fn player_regex_rejects_invalid_patterns() {
        let source = format!("{}\n[players]\njoin_regex = '('\n", minimal_server());
        let err = parse_server(&source)
            .err()
            .unwrap_or_else(|| panic!("invalid pattern should be rejected"));
        assert!(
            err.to_string().contains("invalid regex"),
            "error should say the regex is invalid: {err}"
        );
    }

    #[test]
    fn server_config_requires_name_and_command() {
        let err = parse_server("server_name = \"x\"\n")
            .err()
            .unwrap_or_else(|| panic!("missing command should be rejected"));
        assert!(
            err.to_string().contains("command"),
            "error should mention command: {err}"
        );
        let err = parse_server("command = \"true\"\n")
            .err()
            .unwrap_or_else(|| panic!("missing server_name should be rejected"));
        assert!(
            err.to_string().contains("server_name"),
            "error should mention server_name: {err}"
        );
    }

    #[test]
    fn stop_mode_must_be_signal_or_stdin() {
        let source = format!("{}\n[stop]\nmode = \"kick\"\n", minimal_server());
        let err = parse_server(&source)
            .err()
            .unwrap_or_else(|| panic!("invalid mode should be rejected"));
        assert!(
            err.to_string().contains("signal"),
            "error should mention the allowed modes: {err}"
        );
    }

    #[test]
    fn oidc_config_is_all_or_nothing() {
        let issuer = Some(String::from("https://idp.example.com"));
        let client_id = Some(String::from("client"));
        let client_secret = Some(String::from("secret"));
        let admin = Some(String::from("jack"));

        // No settings at all: the admin login is disabled, not an error.
        assert!(
            OidcConfig::from_values(None, None, None, None).is_ok_and(|config| config.is_none()),
            "no settings should disable the admin login"
        );

        // The complete set parses, and the issuer loses its trailing slash.
        let config = OidcConfig::from_values(
            issuer.clone(),
            client_id.clone(),
            client_secret.clone(),
            admin.clone(),
        )
        .unwrap_or_else(|err| panic!("complete oidc config should be valid: {err}"));
        let config = config.expect("checked is_some above");
        assert_eq!(config.issuer, "https://idp.example.com");
        assert_eq!(config.client_id, "client");
        assert_eq!(config.client_secret, "secret");
        assert_eq!(config.admin_username, "jack");
        assert_eq!(config.authorize_url(), "https://idp.example.com/authorize");
        assert_eq!(config.token_url(), "https://idp.example.com/token");
        assert_eq!(config.userinfo_url(), "https://idp.example.com/userinfo");

        // Every three-of-four subset must be rejected: fail closed.
        let subsets = [
            (
                None,
                client_id.clone(),
                client_secret.clone(),
                admin.clone(),
            ),
            (issuer.clone(), None, client_secret.clone(), admin.clone()),
            (issuer.clone(), client_id.clone(), None, admin),
            (issuer, client_id, client_secret, None),
        ];
        for (index, (issuer, client_id, client_secret, admin)) in subsets.iter().enumerate() {
            let result = OidcConfig::from_values(
                issuer.clone(),
                client_id.clone(),
                client_secret.clone(),
                admin.clone(),
            );
            assert!(
                result.is_err(),
                "dropping setting {index} should be an error, not a silent disable"
            );
        }
    }

    #[test]
    fn state_serializes_with_mc_runner_keys() {
        // Sanity check for the JSON shape the websocket protocol promises.
        let state = json!({
            "version": "0.1.0",
            "connect_url": "localhost:25565",
            "server_name": "test",
            "is_running": false,
            "online_players": [],
            "auto_stop_time": i64::MAX,
            "bot_tag": "",
        });
        assert_eq!(state["bot_tag"], json!(""), "bot_tag stays for parity");
        assert_eq!(state["auto_stop_time"], json!(i64::MAX), "sentinel");
    }
}
