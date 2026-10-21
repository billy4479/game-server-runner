//! Integration tests that drive the real `game-server-runner` binary with a
//! fake game server script, speak the websocket protocol to it, and exercise
//! the auth flows end to end: the OIDC admin login against a mock provider,
//! telegram login with the approval queue, and bans.
//!
//! Cookie handling note: the runner sets `Secure` cookies, and reqwest's
//! cookie jar would refuse to store or resend them over plain http. The
//! tests therefore use no jar: each helper reads the token out of the
//! `Set-Cookie` response header and sends it back manually as
//! `Cookie: <name>=<value>` (and on the websocket upgrade request). This is
//! deterministic and mirrors exactly what the browser frontend does.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::{SinkExt, StreamExt};
use hmac::Hmac;
use hmac::Mac;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio_tungstenite::tungstenite::Message as WsFrame;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue as WsHeaderValue;
use tokio_tungstenite::tungstenite::http::Request as WsRequest;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

const MESSAGE_TIMEOUT: Duration = Duration::from_secs(15);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);
/// Sessions slide forward by this many seconds on every authenticated
/// request; the rotation test needs the clock to move at least one second.
const ROTATION_SLEEP: Duration = Duration::from_millis(1100);

/// The tailnet identity the mock provider authenticates as the admin.
const ADMIN_USERNAME: &str = "jack";
/// OAuth client credentials shared by the runner env and the mock provider.
const OIDC_CLIENT_ID: &str = "test-client";
const OIDC_CLIENT_SECRET: &str = "test-secret";
/// The one authorization code the mock provider hands out.
const OIDC_CODE: &str = "test-code";
/// The access token bound to that code.
const OIDC_ACCESS_TOKEN: &str = "mock-access-token";
/// Bot credentials the telegram login tests sign payloads with.
const TELEGRAM_BOT_TOKEN: &str = "12345:test-bot-token";
const TELEGRAM_BOT_USERNAME: &str = "test_bot";

/// Fake game server: handles `join <name>`, `leave <name>`, `stop` and
/// `crash` console commands, exits 0 on SIGTERM within its read timeout.
const FAKE_SERVER_SCRIPT: &str = r#"#!/usr/bin/env bash
echo $$ > server.pid
stop=0
trap 'stop=1' TERM
echo "fake server starting"
while [ "$stop" -eq 0 ]; do
  IFS= read -r -t 1 line
  rc=$?
  if [ "$rc" -eq 0 ]; then
    case "$line" in
      join\ *) echo "${line#join } joined the game" ;;
      leave\ *) echo "${line#leave } left the game" ;;
      stop) echo "stopping"; exit 0 ;;
      crash) echo "crashing"; exit 1 ;;
    esac
  elif [ "$rc" -gt 128 ]; then
    :
  else
    break
  fi
done
echo "stopping"
exit 0
"#;

/// Fake game server that ignores SIGTERM on purpose: only a SIGKILL from the
/// escalation path can end it.
const STUBBORN_SCRIPT: &str = r#"#!/usr/bin/env bash
echo $$ > stubborn.pid
trap 'echo trapped > marker.txt' TERM
echo "stubborn server starting"
while :; do
  sleep 5 &
  wait $!
done
"#;

/// Fake `restic`: appends its argv to `restic-args.log` in the working
/// directory (the runner's temp dir) and exits 0.
const FAKE_RESTIC_SCRIPT: &str = r#"#!/usr/bin/env bash
printf '%s\n' "$*" >> restic-args.log
exit 0
"#;

fn lifecycle_server_toml() -> String {
    String::from(
        r#"server_name = "lifecycle"
command = "bash"
args = ["fake-server.sh"]

[players]
join_regex = '^(?P<player>\S+) joined the game'
leave_regex = '^(?P<player>\S+) left the game'
"#,
    )
}

fn stubborn_server_toml() -> String {
    String::from(
        r#"server_name = "stubborn"
command = "bash"
args = ["stubborn.sh"]

[stop]
mode = "signal"
payload = "SIGTERM"
grace_period = "1s"
"#,
    )
}

// --- mock oidc provider -----------------------------------------------------

/// Shared state of the mock provider, so tests can stage each attempt.
#[derive(Default)]
struct IdpState {
    /// The S256 challenge seen in the authorize redirect, verified against
    /// the presented `code_verifier`.
    challenge: Mutex<Option<String>>,
    /// The `redirect_uri` the runner used, echoed by the token endpoint.
    redirect_uri: Mutex<Option<String>>,
    /// The authorization code is single-use.
    code_used: Mutex<bool>,
    /// The username claim served by /userinfo.
    username: Mutex<String>,
    /// When set, the token endpoint refuses the exchange.
    reject_exchange: Mutex<bool>,
}

/// Minimal stand-in for tsidp: a blocking TCP server speaking just enough
/// HTTP for the two endpoints the runner calls, `/token` and `/userinfo`.
struct MockIdp {
    port: u16,
    state: Arc<IdpState>,
}

impl MockIdp {
    fn new(admin_username: &str) -> Result<Self, String> {
        let state = Arc::new(IdpState {
            username: Mutex::new(admin_username.to_string()),
            ..IdpState::default()
        });
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|err| format!("bind mock idp: {err}"))?;
        let port = listener
            .local_addr()
            .map_err(|err| format!("mock idp address: {err}"))?
            .port();
        let served = Arc::clone(&state);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let state = Arc::clone(&served);
                std::thread::spawn(move || handle_idp_connection(stream, &state));
            }
        });
        Ok(Self { port, state })
    }

    fn issuer(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

/// Stage the provider for one login attempt.
fn stage_idp(
    state: &IdpState,
    challenge: Option<String>,
    redirect_uri: Option<String>,
    username: &str,
    code_used: bool,
    reject_exchange: bool,
) {
    *state
        .challenge
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = challenge;
    *state
        .redirect_uri
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = redirect_uri;
    *state
        .username
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = username.to_string();
    *state
        .code_used
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = code_used;
    *state
        .reject_exchange
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = reject_exchange;
}

fn handle_idp_connection(mut stream: std::net::TcpStream, state: &Arc<IdpState>) {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(read) => {
                if let Some(bytes) = chunk.get(..read) {
                    buffer.extend_from_slice(bytes);
                }
            }
        }
        if let Some(position) = find(&buffer, b"\r\n\r\n") {
            break position;
        }
    };
    let head = buffer
        .get(..header_end)
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        .unwrap_or_default();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().unwrap_or(0);
        }
    }
    let body_start = header_end.saturating_add(4);
    let body_end = body_start.saturating_add(content_length);
    while buffer.len() < body_end {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                if let Some(bytes) = chunk.get(..read) {
                    buffer.extend_from_slice(bytes);
                }
            }
        }
    }
    let body = buffer.get(body_start..).unwrap_or(&[]).to_vec();

    let (status, payload) = match (method.as_str(), path.split('?').next().unwrap_or_default()) {
        ("POST", "/token") => idp_token_endpoint(&body, state),
        ("GET", "/userinfo") => idp_userinfo_endpoint(&head, state),
        _ => (404, json!({ "error": "not_found" }).to_string()),
    };
    let response = format!(
        "HTTP/1.1 {status} mock\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    if stream.write_all(response.as_bytes()).is_err() {
        return;
    }
    let Ok(()) = stream.flush() else {
        return;
    };
}

/// The token endpoint: verify the client credentials, the one-shot code,
/// the redirect uri and the PKCE verifier, then hand out the access token.
fn idp_token_endpoint(body: &[u8], state: &IdpState) -> (u16, String) {
    if *state
        .reject_exchange
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
    {
        return (400, json!({ "error": "invalid_grant" }).to_string());
    }
    let form: BTreeMap<String, String> = String::from_utf8_lossy(body)
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(name, value)| (percent_decode(name), percent_decode(value)))
        .collect();
    let value = |key: &str| form.get(key).cloned().unwrap_or_default();
    if value("grant_type") != "authorization_code"
        || value("code") != OIDC_CODE
        || value("client_id") != OIDC_CLIENT_ID
        || value("client_secret") != OIDC_CLIENT_SECRET
    {
        return (400, json!({ "error": "invalid_client" }).to_string());
    }

    // PKCE S256: the presented verifier must hash to the staged challenge.
    let verifier = value("code_verifier");
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    if state
        .challenge
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_deref()
        != Some(challenge.as_str())
    {
        return (400, json!({ "error": "invalid_grant" }).to_string());
    }
    if state
        .redirect_uri
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_deref()
        != Some(value("redirect_uri").as_str())
    {
        return (400, json!({ "error": "invalid_grant" }).to_string());
    }

    // The code is single-use; burn it only after every check passed.
    {
        let mut code_used = state
            .code_used
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *code_used {
            return (400, json!({ "error": "invalid_grant" }).to_string());
        }
        *code_used = true;
    }
    (
        200,
        json!({ "access_token": OIDC_ACCESS_TOKEN, "token_type": "Bearer" }).to_string(),
    )
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// The userinfo endpoint: identity claims ride on the opaque access token,
/// never on a parsed ID token.
fn idp_userinfo_endpoint(head: &str, state: &IdpState) -> (u16, String) {
    let authorized = head.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.trim().eq_ignore_ascii_case("authorization")
            && value.trim() == format!("Bearer {OIDC_ACCESS_TOKEN}")
    });
    if !authorized {
        return (401, json!({ "error": "invalid_token" }).to_string());
    }
    let username = state
        .username
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    (
        200,
        json!({
            "sub": "userid:1",
            "username": username,
            "name": "Jack",
            "email": "jack@mail.polpetta.online",
        })
        .to_string(),
    )
}

type WsClient = WebSocketStream<MaybeTlsStream<TcpStream>>;
fn next_port() -> u16 {
    static PORT: AtomicU16 = AtomicU16::new(39_560);
    PORT.fetch_add(1, Ordering::SeqCst)
}

struct TestRunner {
    _dir: TempDir,
    child: Child,
    port: u16,
    server_dir: PathBuf,
    db_path: PathBuf,
    /// Argv log of the fake restic binary; only exists after a backup ran.
    restic_log: PathBuf,
    stderr: Arc<Mutex<Vec<u8>>>,
    idp: MockIdp,
}

/// Optional configuration knobs for [`TestRunner::spawn_full`].
#[derive(Default)]
struct SpawnExtras<'a> {
    restic_repo: Option<&'a str>,
    /// Configure telegram login with the shared test bot credentials.
    telegram: bool,
    extra_env: Vec<(String, String)>,
}

impl TestRunner {
    /// Write the config files and spawn the real binary in the temp dir,
    /// with stderr captured into a shared buffer the tests can grep. The
    /// OIDC admin login is always configured against a fresh mock provider.
    fn spawn(
        minutes_before_stop: u64,
        server_toml: &str,
        script_name: &str,
        server_script: &str,
    ) -> Result<Self, String> {
        Self::spawn_full(
            minutes_before_stop,
            server_toml,
            script_name,
            server_script,
            SpawnExtras::default(),
        )
    }

    /// Like [`TestRunner::spawn`], but with `restic_repo` set: a fake restic
    /// binary is installed and restic backups are enabled with that repo
    /// marker. Telegram stays disabled, the default.
    fn spawn_with_config(
        minutes_before_stop: u64,
        server_toml: &str,
        script_name: &str,
        server_script: &str,
        restic_repo: Option<&str>,
    ) -> Result<Self, String> {
        Self::spawn_full(
            minutes_before_stop,
            server_toml,
            script_name,
            server_script,
            SpawnExtras {
                restic_repo,
                ..SpawnExtras::default()
            },
        )
    }

    /// Like [`TestRunner::spawn`], with telegram login configured.
    fn spawn_with_telegram(
        minutes_before_stop: u64,
        server_toml: &str,
        script_name: &str,
        server_script: &str,
    ) -> Result<Self, String> {
        Self::spawn_full(
            minutes_before_stop,
            server_toml,
            script_name,
            server_script,
            SpawnExtras {
                telegram: true,
                ..SpawnExtras::default()
            },
        )
    }

    fn spawn_full(
        minutes_before_stop: u64,
        server_toml: &str,
        script_name: &str,
        server_script: &str,
        extras: SpawnExtras<'_>,
    ) -> Result<Self, String> {
        let port = next_port();
        let idp = MockIdp::new(ADMIN_USERNAME)?;
        let dir = TempDir::new().map_err(|err| format!("create temp dir: {err}"))?;
        let mut config = format!(
            "db_path = 'test.db'\n\
             port = {port}\n\
             connect_url = 'localhost:25565'\n\
             server_dir = 'server'\n\
             minutes_before_stop = {minutes_before_stop}\n\
             log_level = 'debug'\n"
        );
        if extras.telegram
            && let Err(err) = write!(
                config,
                "\n[telegram]\ntoken = '{TELEGRAM_BOT_TOKEN}'\nusername = '{TELEGRAM_BOT_USERNAME}'\nchat_ids = '999999'\n"
            )
        {
            return Err(format!("format telegram config: {err}"));
        }
        if let Some(repo) = extras.restic_repo {
            let restic_script = dir.path().join("fake-restic.sh");
            std::fs::write(&restic_script, FAKE_RESTIC_SCRIPT)
                .map_err(|err| format!("write fake restic script: {err}"))?;
            set_executable(&restic_script)?;
            if let Err(err) = write!(
                config,
                "restic_enable = true\n\
                 restic_path = '{}'\n\
                 restic_repo = '{repo}'\n",
                restic_script.display()
            ) {
                return Err(format!("format restic config: {err}"));
            }
        }
        std::fs::write(dir.path().join("config.toml"), config)
            .map_err(|err| format!("write config.toml: {err}"))?;

        let server_dir = dir.path().join("server");
        std::fs::create_dir_all(&server_dir).map_err(|err| format!("create server dir: {err}"))?;
        std::fs::write(server_dir.join("server.toml"), server_toml)
            .map_err(|err| format!("write server.toml: {err}"))?;
        let script_path = server_dir.join(script_name);
        std::fs::write(&script_path, server_script)
            .map_err(|err| format!("write fake server script: {err}"))?;
        set_executable(&script_path)?;

        let mut env = vec![
            (String::from("OIDC_ISSUER"), idp.issuer()),
            (String::from("OIDC_CLIENT_ID"), String::from(OIDC_CLIENT_ID)),
            (
                String::from("OIDC_CLIENT_SECRET"),
                String::from(OIDC_CLIENT_SECRET),
            ),
            (String::from("ADMIN_USERNAME"), String::from(ADMIN_USERNAME)),
        ];
        env.extend(extras.extra_env);
        let mut child = Command::new(env!("CARGO_BIN_EXE_game-server-runner"))
            .current_dir(dir.path())
            .env("CONFIG_PATH", dir.path().join("config.toml"))
            .envs(env)
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| format!("spawn game-server-runner: {err}"))?;

        let stderr_pipe = child
            .stderr
            .take()
            .ok_or_else(|| String::from("runner stderr is not piped"))?;
        let stderr = Arc::new(Mutex::new(Vec::new()));
        spawn_stderr_reader(stderr_pipe, Arc::clone(&stderr));

        let db_path = dir.path().join("test.db");
        let restic_log = dir.path().join("restic-args.log");
        Ok(Self {
            _dir: dir,
            child,
            port,
            server_dir,
            db_path,
            restic_log,
            stderr,
            idp,
        })
    }

    fn pid(&self) -> Result<u32, String> {
        self.child
            .id()
            .ok_or_else(|| String::from("runner process has already exited"))
    }

    async fn console_write(&mut self, line: &str) -> Result<(), String> {
        let stdin = self
            .child
            .stdin
            .as_mut()
            .ok_or_else(|| String::from("runner stdin is not piped"))?;
        stdin
            .write_all(line.as_bytes())
            .await
            .map_err(|err| format!("write to runner stdin: {err}"))?;
        stdin
            .flush()
            .await
            .map_err(|err| format!("flush runner stdin: {err}"))?;
        Ok(())
    }

    /// Pid file written by the fake server inside the server dir.
    fn server_pid(&self, pid_file: &str) -> Result<u32, String> {
        let raw = std::fs::read_to_string(self.server_dir.join(pid_file))
            .map_err(|err| format!("read {pid_file}: {err}"))?;
        raw.trim()
            .parse()
            .map_err(|err| format!("parse server pid from {raw:?}: {err}"))
    }

    fn stderr_text(&self) -> String {
        let buffer = self.stderr.lock().unwrap_or_else(PoisonError::into_inner);
        String::from_utf8_lossy(&buffer).into_owned()
    }
}

fn spawn_stderr_reader(mut pipe: tokio::process::ChildStderr, sink: Arc<Mutex<Vec<u8>>>) {
    tokio::spawn(async move {
        let mut chunk = [0u8; 4096];
        loop {
            match pipe.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    if let Some(bytes) = chunk.get(..read) {
                        let mut buffer = sink.lock().unwrap_or_else(PoisonError::into_inner);
                        buffer.extend_from_slice(bytes);
                    }
                }
            }
        }
    });
}

impl Drop for TestRunner {
    fn drop(&mut self) {
        // Best effort teardown; the tests assert the graceful paths.
        match self.child.start_kill() {
            Ok(()) | Err(_) => {}
        }
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(2))
            .unwrap_or_else(Instant::now);
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }
}

fn set_executable(path: &Path) -> Result<(), String> {
    let mut perms = std::fs::metadata(path)
        .map_err(|err| format!("stat {}: {err}", path.display()))?
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).map_err(|err| format!("chmod {}: {err}", path.display()))
}

async fn send_signal(pid: u32, signal: &str) -> Result<(), String> {
    let status = Command::new("kill")
        .args([format!("-{signal}"), pid.to_string()])
        .status()
        .await
        .map_err(|err| format!("run kill: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("kill -{signal} {pid} failed"))
    }
}

async fn process_alive(pid: u32) -> Result<bool, String> {
    let status = Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .await
        .map_err(|err| format!("run kill -0: {err}"))?;
    Ok(status.success())
}

async fn wait_for_exit(
    child: &mut Child,
    timeout: Duration,
) -> Result<Option<std::process::ExitStatus>, String> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    loop {
        let status = child.try_wait().map_err(|err| format!("try_wait: {err}"))?;
        if let Some(status) = status {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// SIGTERM the runner and require a clean exit code.
async fn graceful_shutdown(harness: &mut TestRunner) -> Result<(), String> {
    let pid = harness.pid()?;
    send_signal(pid, "TERM").await?;
    let status = wait_for_exit(&mut harness.child, SHUTDOWN_TIMEOUT)
        .await?
        .ok_or_else(|| format!("runner did not exit within {SHUTDOWN_TIMEOUT:?} of SIGTERM"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("runner exit status: {status}"))
    }
}

async fn http_get(port: u16, path: &str) -> Result<(u16, String), String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|err| format!("connect: {err}"))?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|err| format!("write request: {err}"))?;
    let mut buffer = Vec::new();
    stream
        .read_to_end(&mut buffer)
        .await
        .map_err(|err| format!("read response: {err}"))?;
    let response = String::from_utf8_lossy(&buffer).to_string();
    let status: u16 = response
        .strip_prefix("HTTP/1.1 ")
        .and_then(|rest| rest.get(..3))
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| format!("no status line in {response:?}"))?;
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.trim().to_string())
        .unwrap_or_default();
    Ok((status, body))
}

async fn wait_until_listening(port: u16) -> Result<(), String> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(15))
        .unwrap_or_else(Instant::now);
    loop {
        if let Ok((200, body)) = http_get(port, "/api/ping").await
            && body == "pong"
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "runner did not start listening on port {port} in time"
            ));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// --- auth helpers -----------------------------------------------------------

struct HttpResponse {
    status: u16,
    /// Every `Set-Cookie` header, in response order.
    set_cookies: Vec<String>,
    location: Option<String>,
    body: String,
}

/// One JSON HTTP request with an optional manual `Cookie: name=value`
/// header. Redirects are never followed: the OIDC endpoints answer with
/// 3xx and the tests read the Location header themselves. Cookies are never
/// stored in a jar; see the module comment.
async fn http_request(
    port: u16,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
    cookie: Option<(&str, &str)>,
) -> Result<HttpResponse, String> {
    let client = reqwest::Client::builder()
        .timeout(MESSAGE_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| format!("build http client: {err}"))?;
    let mut request = client.request(method, format!("http://127.0.0.1:{port}{path}"));
    if let Some(body) = body {
        request = request.json(&body);
    }
    if let Some((name, value)) = cookie {
        request = request.header(reqwest::header::COOKIE, format!("{name}={value}"));
    }
    let response = request
        .send()
        .await
        .map_err(|err| format!("http request to {path}: {err}"))?;
    let status = response.status().as_u16();
    let set_cookies = response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_string)
        .collect();
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let body = response
        .text()
        .await
        .map_err(|err| format!("http body of {path}: {err}"))?;
    Ok(HttpResponse {
        status,
        set_cookies,
        location,
        body,
    })
}

/// Extract the token from the first `name=value; attributes` Set-Cookie
/// header carrying `name`.
fn cookie_from_set_cookie(set_cookies: &[String], name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    let raw = set_cookies
        .iter()
        .find(|cookie| cookie.starts_with(&prefix))?;
    let value = raw.strip_prefix(&prefix)?;
    let end = value.find(';').unwrap_or(value.len());
    value.get(..end).map(str::to_string)
}

/// Drive the OIDC login against the mock provider. Returns the raw callback
/// response: a success carries the session cookie, failures their status.
/// `return_to` rides through as the post-login destination, like the SPA
/// sends it.
async fn oidc_login_attempt(
    harness: &TestRunner,
    username: &str,
    return_to: Option<&str>,
) -> Result<HttpResponse, String> {
    let attempt_url = return_to.map_or_else(
        || String::from("/api/auth/oidc/login"),
        |path| format!("/api/auth/oidc/login?return_to={path}"),
    );
    let start = http_request(harness.port, reqwest::Method::GET, &attempt_url, None, None).await?;
    if start.status != 303 {
        return Ok(start);
    }
    let location = start
        .location
        .clone()
        .ok_or_else(|| String::from("the oidc login redirect carries no location"))?;
    let query = location
        .split_once('?')
        .map_or(String::new(), |(_, query)| query.to_string());
    let query = query.as_str();
    let mut params: BTreeMap<String, String> = BTreeMap::new();
    for pair in query.split('&') {
        if let Some((name, value)) = pair.split_once('=') {
            params.insert(percent_decode(name), percent_decode(value));
        }
    }
    let state_token = params
        .get("state")
        .cloned()
        .ok_or_else(|| String::from("authorize url has no state"))?;
    let challenge = params
        .get("code_challenge")
        .cloned()
        .ok_or_else(|| String::from("authorize url has no code_challenge"))?;
    let redirect_uri = params
        .get("redirect_uri")
        .cloned()
        .ok_or_else(|| String::from("authorize url has no redirect_uri"))?;

    // Stage the provider: accept this challenge and redirect, serve this
    // identity, hand out a fresh code.
    stage_idp(
        &harness.idp.state,
        Some(challenge),
        Some(redirect_uri),
        username,
        false,
        false,
    );

    let state_cookie = cookie_from_set_cookie(&start.set_cookies, "oidc_login")
        .ok_or_else(|| String::from("the login redirect carries no state cookie"))?;
    http_request(
        harness.port,
        reqwest::Method::GET,
        &format!("/api/auth/oidc/callback?code={OIDC_CODE}&state={state_token}"),
        None,
        Some(("oidc_login", state_cookie.as_str())),
    )
    .await
}

/// The mock provider of a harness.
/// Bootstrap an admin session by driving the whole OIDC flow.
async fn admin_session(harness: &TestRunner) -> Result<String, String> {
    let attempt = oidc_login_attempt(harness, ADMIN_USERNAME, None).await?;
    if attempt.status != 303 {
        return Err(format!(
            "oidc callback failed: {} {}",
            attempt.status, attempt.body
        ));
    }
    cookie_from_set_cookie(&attempt.set_cookies, "auth")
        .ok_or_else(|| String::from("the oidc callback carries no session cookie"))
}

/// Sign `fields` exactly the way the telegram backend does, returning the
/// payload with its `hash` field. Non-scalar fields are ignored; the
/// fixtures only ever use strings and numbers.
fn signed_telegram_payload(mut fields: serde_json::Map<String, Value>) -> Value {
    let mut pairs: BTreeMap<String, String> = BTreeMap::new();
    for (key, value) in &fields {
        match value {
            Value::String(text) => {
                pairs.insert(key.clone(), text.clone());
            }
            Value::Number(number) => {
                pairs.insert(key.clone(), number.to_string());
            }
            _ => {}
        }
    }
    let check = pairs
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("\n");
    let secret = Sha256::digest(TELEGRAM_BOT_TOKEN.as_bytes());
    // The hmac crate accepts any key length, so this cannot fail; a fixture
    // may not panic, hence the silent fallback.
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&secret) else {
        return Value::Null;
    };
    mac.update(check.as_bytes());
    fields.insert(
        String::from("hash"),
        Value::String(hex_encode(&mac.finalize().into_bytes())),
    );
    Value::Object(fields)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let high = HEX.get(usize::from(byte >> 4)).copied().unwrap_or(b'?');
        let low = HEX.get(usize::from(byte & 15)).copied().unwrap_or(b'?');
        out.push(char::from(high));
        out.push(char::from(low));
    }
    out
}

/// A valid, fresh login payload for the given telegram id.
fn telegram_payload(id: i64, username: &str) -> Value {
    let mut fields = serde_json::Map::new();
    fields.insert(String::from("id"), Value::from(id));
    fields.insert(String::from("first_name"), Value::from(username));
    fields.insert(String::from("username"), Value::from(username));
    fields.insert(String::from("auth_date"), Value::from(now_secs()));
    signed_telegram_payload(fields)
}

/// Wall clock seconds, saturated; a plain-fn twin of the runner's clock
/// helper, because helpers outside `#[test]` functions may not panic.
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(i64::MAX, |delta| {
            i64::try_from(delta.as_secs()).unwrap_or(i64::MAX)
        })
}

async fn telegram_login(port: u16, payload: Value) -> Result<HttpResponse, String> {
    http_request(
        port,
        reqwest::Method::POST,
        "/api/auth/telegram",
        Some(payload),
        None,
    )
    .await
}

/// Authenticated GET /api/auth/me. Rotates `cookie` in place when the
/// response carries a new one.
async fn me(port: u16, cookie: &mut String) -> Result<(u16, Value), String> {
    let response = http_request(
        port,
        reqwest::Method::GET,
        "/api/auth/me",
        None,
        Some(("auth", cookie.as_str())),
    )
    .await?;
    if let Some(updated) = cookie_from_set_cookie(&response.set_cookies, "auth") {
        *cookie = updated;
    }
    let body: Value = serde_json::from_str(&response.body).unwrap_or(Value::Null);
    Ok((response.status, body))
}

/// Authenticated DELETE /api/auth/logout; rotates `cookie` in place and
/// returns the status.
async fn logout(port: u16, cookie: &mut String) -> Result<u16, String> {
    let response = http_request(
        port,
        reqwest::Method::DELETE,
        "/api/auth/logout",
        None,
        Some(("auth", cookie.as_str())),
    )
    .await?;
    if let Some(updated) = cookie_from_set_cookie(&response.set_cookies, "auth") {
        *cookie = updated;
    }
    Ok(response.status)
}

/// Authenticated GET /api/admin/pending.
async fn admin_list_pending(port: u16, cookie: &mut String) -> Result<(u16, Value), String> {
    let response = http_request(
        port,
        reqwest::Method::GET,
        "/api/admin/pending",
        None,
        Some(("auth", cookie.as_str())),
    )
    .await?;
    if let Some(updated) = cookie_from_set_cookie(&response.set_cookies, "auth") {
        *cookie = updated;
    }
    let body: Value = serde_json::from_str(&response.body).unwrap_or(Value::Null);
    Ok((response.status, body))
}

/// Authenticated POST /api/admin/pending/{id}/approve|deny.
async fn admin_pending_action(
    port: u16,
    cookie: &mut String,
    telegram_id: i64,
    action: &str,
) -> Result<u16, String> {
    let response = http_request(
        port,
        reqwest::Method::POST,
        &format!("/api/admin/pending/{telegram_id}/{action}"),
        None,
        Some(("auth", cookie.as_str())),
    )
    .await?;
    if let Some(updated) = cookie_from_set_cookie(&response.set_cookies, "auth") {
        *cookie = updated;
    }
    Ok(response.status)
}

/// Authenticated POST /api/admin/users/{id}/ban|unban.
async fn admin_ban_action(
    port: u16,
    cookie: &mut String,
    user_id: i64,
    action: &str,
) -> Result<u16, String> {
    let response = http_request(
        port,
        reqwest::Method::POST,
        &format!("/api/admin/users/{user_id}/{action}"),
        None,
        Some(("auth", cookie.as_str())),
    )
    .await?;
    if let Some(updated) = cookie_from_set_cookie(&response.set_cookies, "auth") {
        *cookie = updated;
    }
    Ok(response.status)
}

/// Open the runner's `SQLite` database for inspection.
async fn open_db(path: &Path) -> Result<SqlitePool, String> {
    let options = SqliteConnectOptions::new().filename(path);
    SqlitePool::connect_with(options)
        .await
        .map_err(|err| format!("open test database: {err}"))
}

fn unix_now() -> Result<i64, String> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("clock before the epoch: {err}"))?
        .as_secs();
    i64::try_from(secs).map_err(|err| format!("unix time does not fit i64: {err}"))
}

fn percent_decode(value: &str) -> String {
    let with_spaces = value.replace('+', " ");
    let mut out: Vec<u8> = Vec::with_capacity(with_spaces.len());
    let mut bytes = with_spaces.as_bytes().iter().copied();
    while let Some(byte) = bytes.next() {
        if byte != b'%' {
            out.push(byte);
            continue;
        }
        let high = bytes
            .next()
            .and_then(|digit| char::from(digit).to_digit(16));
        let low = bytes
            .next()
            .and_then(|digit| char::from(digit).to_digit(16));
        let decoded = match (high, low) {
            (Some(high), Some(low)) => high
                .checked_mul(16)
                .and_then(|value| value.checked_add(low))
                .and_then(|value| u8::try_from(value).ok()),
            _ => None,
        };
        match decoded {
            Some(byte) => out.push(byte),
            None => out.push(b'%'),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// --- websocket helpers ------------------------------------------------------

fn ws_request(port: u16, cookie: Option<&str>) -> Result<WsRequest<()>, String> {
    let mut request = format!("ws://127.0.0.1:{port}/api/ws")
        .into_client_request()
        .map_err(|err| format!("build websocket request: {err}"))?;
    if let Some(cookie) = cookie {
        let value = WsHeaderValue::from_str(&format!("auth={cookie}"))
            .map_err(|err| format!("cookie header value: {err}"))?;
        request.headers_mut().insert("Cookie", value);
    }
    Ok(request)
}

async fn ws_connect(port: u16, cookie: Option<&str>) -> Result<WsClient, String> {
    let request = ws_request(port, cookie)?;
    let connection = tokio::time::timeout(MESSAGE_TIMEOUT, connect_async(request))
        .await
        .map_err(|_elapsed| format!("timed out connecting to the websocket on port {port}"))?;
    let (stream, _) = connection.map_err(|err| format!("websocket connect failed: {err}"))?;
    Ok(stream)
}

async fn ws_send(ws: &mut WsClient, text: &str) -> Result<(), String> {
    let sent = tokio::time::timeout(MESSAGE_TIMEOUT, ws.send(WsFrame::text(text)))
        .await
        .map_err(|_elapsed| format!("timed out sending {text:?}"))?;
    sent.map_err(|err| format!("sending {text:?} failed: {err}"))
}

struct Envelope {
    kind: String,
    data: Value,
}

async fn next_envelope(ws: &mut WsClient) -> Result<Envelope, String> {
    loop {
        let received = tokio::time::timeout(MESSAGE_TIMEOUT, ws.next())
            .await
            .map_err(|_elapsed| String::from("timed out waiting for a websocket message"))?;
        let Some(frame) = received else {
            return Err(String::from("websocket stream ended unexpectedly"));
        };
        let frame = frame.map_err(|err| format!("websocket protocol error: {err}"))?;
        let WsFrame::Text(text) = frame else {
            continue; // pings, pongs and binary frames are not feed messages
        };
        let value: Value = serde_json::from_str(text.as_str())
            .map_err(|err| format!("feed message is not JSON: {err}"))?;
        let kind = value
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("feed message has no type: {value}"))?
            .to_string();
        let data = value.get("data").cloned().unwrap_or(Value::Null);
        break Ok(Envelope { kind, data });
    }
}

async fn next_state(ws: &mut WsClient) -> Result<Value, String> {
    loop {
        let envelope = next_envelope(ws).await?;
        if envelope.kind == "state" {
            return Ok(envelope.data);
        }
    }
}

/// Collect state messages until the predicate matches.
async fn wait_for_state(
    ws: &mut WsClient,
    predicate: impl Fn(&Value) -> bool,
) -> Result<Value, String> {
    let deadline = Instant::now()
        .checked_add(STARTUP_TIMEOUT)
        .unwrap_or_else(Instant::now);
    loop {
        if Instant::now() >= deadline {
            return Err(String::from(
                "timed out waiting for the expected state message",
            ));
        }
        let state = next_state(ws).await?;
        if predicate(&state) {
            return Ok(state);
        }
    }
}

async fn is_running_state(ws: &mut WsClient, running: bool) -> Result<Value, String> {
    let wanted = json!(running);
    wait_for_state(ws, |state| state.get("is_running") == Some(&wanted)).await
}

/// Send `start` over the websocket and wait for the running state, requiring
/// the server banner to show up in the chat feed on the way.
async fn start_server_via_ws(ws: &mut WsClient) -> Result<(), String> {
    let mut saw_banner = false;
    let mut saw_running = false;
    let deadline = Instant::now()
        .checked_add(STARTUP_TIMEOUT)
        .unwrap_or_else(Instant::now);
    ws_send(ws, "start").await?;
    let running = json!(true);
    loop {
        if saw_banner && saw_running {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(String::from("timed out waiting for startup"));
        }
        let envelope = next_envelope(ws).await?;
        match envelope.kind.as_str() {
            "state" if envelope.data.get("is_running") == Some(&running) => {
                saw_running = true;
            }
            "chat"
                if envelope
                    .data
                    .as_str()
                    .is_some_and(|line| line.contains("server starting")) =>
            {
                saw_banner = true;
            }
            _ => {}
        }
    }
}

async fn next_chat(ws: &mut WsClient) -> Result<String, String> {
    loop {
        let envelope = next_envelope(ws).await?;
        if envelope.kind == "chat" {
            return envelope
                .data
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("chat data should be a string: {}", envelope.data));
        }
    }
}

/// The M1 handshake on an authenticated socket: one state snapshot, then the
/// chat history.
async fn read_initial_feed(ws: &mut WsClient) -> Result<Value, String> {
    let state = next_state(ws).await?;
    let history = next_chat(ws).await?;
    Ok(json!({ "state": state, "history": history }))
}

#[tokio::test]
async fn ping_returns_pong() {
    let mut harness = TestRunner::spawn(
        5,
        &lifecycle_server_toml(),
        "fake-server.sh",
        FAKE_SERVER_SCRIPT,
    )
    .expect("spawn harness");
    wait_until_listening(harness.port)
        .await
        .expect("runner did not come up");
    let (status, body) = http_get(harness.port, "/api/ping").await.expect("ping");
    assert_eq!(status, 200, "ping status");
    assert_eq!(body, "pong", "ping body");
    graceful_shutdown(&mut harness)
        .await
        .expect("graceful shutdown");
}

#[tokio::test]
async fn full_lifecycle_start_join_leave_graceful_shutdown() {
    let mut harness = TestRunner::spawn(
        5,
        &lifecycle_server_toml(),
        "fake-server.sh",
        FAKE_SERVER_SCRIPT,
    )
    .expect("spawn harness");
    wait_until_listening(harness.port)
        .await
        .expect("runner did not come up");
    let cookie = admin_session(&harness).await.expect("admin session");
    let mut ws = ws_connect(harness.port, Some(&cookie))
        .await
        .expect("ws connect");

    // Initial handshake: one state snapshot, then the chat history.
    let initial = read_initial_feed(&mut ws).await.expect("initial feed");
    let state = &initial["state"];
    assert_eq!(state["is_running"], json!(false), "initial is_running");
    assert_eq!(state["server_name"], json!("lifecycle"), "server name");
    assert_eq!(state["online_players"], json!([]), "initial players");
    assert_eq!(
        state["auto_stop_time"],
        json!(i64::MAX),
        "no auto stop scheduled initially"
    );
    assert_eq!(
        state["version"],
        json!(env!("CARGO_PKG_VERSION")),
        "version parity"
    );
    assert_eq!(state["bot_tag"], json!(""), "bot_tag parity wart");
    assert_eq!(initial["history"], json!(""), "fresh chat history is empty");

    // Start the server through the websocket.
    start_server_via_ws(&mut ws).await.expect("start via ws");

    // Drive a join through the runner's console forwarding.
    harness
        .console_write("join alice\n")
        .await
        .expect("write join");
    let state = wait_for_state(&mut ws, |state| state["online_players"] == json!(["alice"]))
        .await
        .expect("state with alice online");
    assert_eq!(
        state["online_players"],
        json!(["alice"]),
        "alice should be online"
    );

    harness
        .console_write("leave alice\n")
        .await
        .expect("write leave");
    let state = wait_for_state(&mut ws, |state| state["online_players"] == json!([]))
        .await
        .expect("state with nobody online");
    assert_eq!(
        state["online_players"],
        json!([]),
        "nobody should be online after the leave"
    );

    // SIGTERM the runner: it must stop the fake server and exit 0.
    graceful_shutdown(&mut harness)
        .await
        .expect("graceful shutdown");
    let server_pid = harness.server_pid("server.pid").expect("server pid");
    assert!(
        !process_alive(server_pid).await.expect("kill -0"),
        "the fake server should be gone after the runner exited"
    );
}

#[tokio::test]
async fn auto_stop_stops_empty_server_and_runner_survives() {
    let mut harness = TestRunner::spawn(
        0,
        &lifecycle_server_toml(),
        "fake-server.sh",
        FAKE_SERVER_SCRIPT,
    )
    .expect("spawn harness");
    wait_until_listening(harness.port)
        .await
        .expect("runner did not come up");
    let cookie = admin_session(&harness).await.expect("admin session");
    let mut ws = ws_connect(harness.port, Some(&cookie))
        .await
        .expect("ws connect");
    let initial = read_initial_feed(&mut ws).await.expect("initial feed");
    assert_eq!(initial["state"]["is_running"], json!(false));

    // With minutes = 0 the auto stop fires immediately, long before the fake
    // server could print its banner, so no banner is asserted here.
    ws_send(&mut ws, "start").await.expect("send start");
    let running = json!(true);
    wait_for_state(&mut ws, |state| state.get("is_running") == Some(&running))
        .await
        .expect("running state");
    let state = is_running_state(&mut ws, false)
        .await
        .expect("stopped state");
    assert_eq!(
        state["auto_stop_time"],
        json!(i64::MAX),
        "auto stop time resets to the sentinel after the exit"
    );

    // With minutes = 0 the server is killed so fast that it may die before
    // its script gets to write server.pid; only check what exists.
    if let Ok(raw) = std::fs::read_to_string(harness.server_dir.join("server.pid")) {
        let server_pid: u32 = raw
            .trim()
            .parse()
            .unwrap_or_else(|err| panic!("parse server pid from {raw:?}: {err}"));
        let alive = process_alive(server_pid).await.expect("kill -0");
        assert!(!alive, "the auto-stopped fake server should be gone");
    }

    // The runner must stay alive and must not restart the server.
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(400)).await;
        let (status, body) = http_get(harness.port, "/api/ping").await.expect("ping");
        assert_eq!(status, 200, "runner still serves after auto stop");
        assert_eq!(body, "pong", "runner still healthy after auto stop");
    }
    graceful_shutdown(&mut harness)
        .await
        .expect("graceful shutdown");
}

#[tokio::test]
async fn stop_escalates_to_sigkill_after_grace_period() {
    let mut harness = TestRunner::spawn(5, &stubborn_server_toml(), "stubborn.sh", STUBBORN_SCRIPT)
        .expect("spawn harness");
    wait_until_listening(harness.port)
        .await
        .expect("runner did not come up");
    let cookie = admin_session(&harness).await.expect("admin session");
    let mut ws = ws_connect(harness.port, Some(&cookie))
        .await
        .expect("ws connect");
    let _initial = read_initial_feed(&mut ws).await.expect("initial feed");

    start_server_via_ws(&mut ws).await.expect("start via ws");
    let server_pid = harness.server_pid("stubborn.pid").expect("stubborn pid");
    assert!(
        process_alive(server_pid).await.expect("kill -0"),
        "stubborn server should be up"
    );

    // The runner's own SIGTERM triggers the stop chain: graceful SIGTERM
    // (ignored by the stubborn server), then SIGKILL after the 1s grace.
    graceful_shutdown(&mut harness)
        .await
        .expect("graceful shutdown");

    let marker = harness.server_dir.join("marker.txt");
    let marker_text =
        std::fs::read_to_string(&marker).expect("the TERM trap should have written marker.txt");
    assert_eq!(marker_text.trim(), "trapped", "TERM trap marker content");
    assert!(
        !process_alive(server_pid).await.expect("kill -0"),
        "only the SIGKILL escalation can end the stubborn server, and it must be gone"
    );
}

#[tokio::test]
async fn crash_is_manual_restart_only() {
    let mut harness = TestRunner::spawn(
        5,
        &lifecycle_server_toml(),
        "fake-server.sh",
        FAKE_SERVER_SCRIPT,
    )
    .expect("spawn harness");
    wait_until_listening(harness.port)
        .await
        .expect("runner did not come up");
    let cookie = admin_session(&harness).await.expect("admin session");
    let mut ws = ws_connect(harness.port, Some(&cookie))
        .await
        .expect("ws connect");
    let _initial = read_initial_feed(&mut ws).await.expect("initial feed");

    start_server_via_ws(&mut ws).await.expect("start via ws");
    harness.console_write("crash\n").await.expect("write crash");
    is_running_state(&mut ws, false)
        .await
        .expect("crash observed");

    // Crash policy is manual restart only: no state flip back on its own.
    let (status, body) = http_get(harness.port, "/api/ping").await.expect("ping");
    assert_eq!(status, 200, "runner survives a server crash");
    assert_eq!(body, "pong", "runner healthy after crash");

    // Manual restart through the websocket works.
    start_server_via_ws(&mut ws).await.expect("start via ws");
    graceful_shutdown(&mut harness)
        .await
        .expect("graceful shutdown");
}

#[tokio::test]
async fn clean_exit_runs_restic_backup_before_the_runner_exits() {
    let mut harness = TestRunner::spawn_with_config(
        5,
        &lifecycle_server_toml(),
        "fake-server.sh",
        FAKE_SERVER_SCRIPT,
        Some("/backups/integration-test-repo"),
    )
    .expect("spawn harness");
    wait_until_listening(harness.port)
        .await
        .expect("runner did not come up");
    let cookie = admin_session(&harness).await.expect("admin session");
    let mut ws = ws_connect(harness.port, Some(&cookie))
        .await
        .expect("ws connect");
    let _initial = read_initial_feed(&mut ws).await.expect("initial feed");

    start_server_via_ws(&mut ws).await.expect("start via ws");

    // SIGTERM the runner: it stops the fake server cleanly, which is the
    // only exit flavor that must back up. The runner cannot exit before the
    // backup finished, so the argv log is complete once graceful_shutdown
    // returns.
    graceful_shutdown(&mut harness)
        .await
        .expect("graceful shutdown");

    let args_log = std::fs::read_to_string(&harness.restic_log)
        .expect("a clean exit must have run the restic backup");
    assert_eq!(
        args_log.lines().count(),
        1,
        "exactly one backup should have run: {args_log:?}"
    );
    assert_eq!(
        args_log.trim(),
        "backup server --repo /backups/integration-test-repo",
        "restic argv must be exactly backup <server_dir> --repo <repo>"
    );
}

#[tokio::test]
async fn crash_does_not_run_restic_backup() {
    let mut harness = TestRunner::spawn_with_config(
        5,
        &lifecycle_server_toml(),
        "fake-server.sh",
        FAKE_SERVER_SCRIPT,
        Some("/backups/integration-test-repo"),
    )
    .expect("spawn harness");
    wait_until_listening(harness.port)
        .await
        .expect("runner did not come up");
    let cookie = admin_session(&harness).await.expect("admin session");
    let mut ws = ws_connect(harness.port, Some(&cookie))
        .await
        .expect("ws connect");
    let _initial = read_initial_feed(&mut ws).await.expect("initial feed");

    start_server_via_ws(&mut ws).await.expect("start via ws");
    harness.console_write("crash\n").await.expect("write crash");
    is_running_state(&mut ws, false)
        .await
        .expect("crash observed");
    assert!(
        harness.stderr_text().contains("terminated with an error"),
        "the crash should be reported as an abnormal exit"
    );

    // The crashed run must never back up; shutting the runner down now is a
    // no-op stop (the server is already gone), so no second exit either.
    graceful_shutdown(&mut harness)
        .await
        .expect("graceful shutdown");
    assert!(
        !harness.restic_log.exists(),
        "a crashed server must not be backed up"
    );
}

#[tokio::test]
async fn session_rotates_and_slides_expiry() {
    let harness = TestRunner::spawn(
        5,
        &lifecycle_server_toml(),
        "fake-server.sh",
        FAKE_SERVER_SCRIPT,
    )
    .expect("spawn harness");
    wait_until_listening(harness.port)
        .await
        .expect("runner did not come up");
    let cookie = admin_session(&harness).await.expect("admin session");
    let db = open_db(&harness.db_path).await.expect("open db");

    let before: i64 = sqlx::query_scalar("SELECT expires FROM sessions")
        .fetch_one(&db)
        .await
        .expect("session expiry before rotation");

    // Let at least a second pass so the slid expiry is strictly greater.
    tokio::time::sleep(ROTATION_SLEEP).await;

    // A /me request must rotate the cookie: the response carries a new one.
    let response = http_request(
        harness.port,
        reqwest::Method::GET,
        "/api/auth/me",
        None,
        Some(("auth", cookie.as_str())),
    )
    .await
    .expect("me with the original cookie");
    assert_eq!(response.status, 200, "me with the original cookie");
    let rotated = cookie_from_set_cookie(&response.set_cookies, "auth")
        .expect("the response must rotate the session cookie");
    assert_ne!(rotated, cookie, "rotation must produce a new token");

    // Replaying the old cookie must fail: the session moved on.
    let replay = http_request(
        harness.port,
        reqwest::Method::GET,
        "/api/auth/me",
        None,
        Some(("auth", cookie.as_str())),
    )
    .await
    .expect("replay of the old cookie");
    assert_eq!(replay.status, 401, "the old cookie must be invalid");

    // The rotated cookie still works.
    let mut live_cookie = rotated.clone();
    let (status, _) = me(harness.port, &mut live_cookie)
        .await
        .expect("me with the rotated cookie");
    assert_eq!(status, 200, "the rotated cookie must work");

    // One session row, expiry moved forward.
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
        .fetch_one(&db)
        .await
        .expect("count sessions");
    assert_eq!(count, 1, "rotation replaces the session in place");
    let after: i64 = sqlx::query_scalar("SELECT expires FROM sessions")
        .fetch_one(&db)
        .await
        .expect("session expiry after rotation");
    assert!(after > before, "sliding expiry must move forward");
}

#[tokio::test]
async fn websocket_requires_an_authenticated_cookie() {
    let mut harness = TestRunner::spawn(
        5,
        &lifecycle_server_toml(),
        "fake-server.sh",
        FAKE_SERVER_SCRIPT,
    )
    .expect("spawn harness");
    wait_until_listening(harness.port)
        .await
        .expect("runner did not come up");
    let cookie = admin_session(&harness).await.expect("admin session");

    // No cookie: the upgrade handshake must be rejected with 401.
    let request = ws_request(harness.port, None).expect("ws request without cookie");
    let outcome = tokio::time::timeout(MESSAGE_TIMEOUT, connect_async(request))
        .await
        .expect("timed out on the unauthenticated websocket connect");
    let Err(error) = outcome else {
        panic!("the websocket upgrade must be rejected without a session cookie");
    };
    let status = match &error {
        tokio_tungstenite::tungstenite::Error::Http(response) => response.status(),
        other => panic!("unexpected websocket error: {other}"),
    };
    assert_eq!(status, 401, "unauthenticated upgrade should be 401");

    // With a valid cookie the M1 protocol works as before.
    let mut ws = ws_connect(harness.port, Some(&cookie))
        .await
        .expect("authed ws connect");
    let initial = read_initial_feed(&mut ws).await.expect("initial feed");
    assert_eq!(
        initial["state"]["is_running"],
        json!(false),
        "initial state"
    );
    assert_eq!(initial["history"], json!(""), "fresh history");
    graceful_shutdown(&mut harness)
        .await
        .expect("graceful shutdown");
}

// --- oidc admin login -------------------------------------------------------

/// Whatever an unauthenticated admin's SPA does on `/admin`: navigate to
/// `/api/auth/oidc/login?return_to=/admin`, come back through the provider,
/// and land on `/admin` with the session and the auto-redirect marker set.
#[tokio::test]
async fn oidc_admin_logs_in_from_the_admin_page_and_lands_back_on_it() {
    let harness = TestRunner::spawn(
        5,
        &lifecycle_server_toml(),
        "fake-server.sh",
        FAKE_SERVER_SCRIPT,
    )
    .expect("spawn harness");
    wait_until_listening(harness.port)
        .await
        .expect("runner did not come up");

    let attempt = oidc_login_attempt(&harness, ADMIN_USERNAME, Some("/admin"))
        .await
        .expect("admin login attempt from /admin");
    assert_eq!(attempt.status, 303, "login succeeded");
    assert_eq!(
        attempt.location.as_deref(),
        Some("/admin"),
        "the post-login destination is the page that started the login"
    );
    assert!(
        attempt
            .set_cookies
            .iter()
            .any(|cookie| cookie.starts_with("was_admin=1")),
        "a completed admin login must mark the browser"
    );

    // A tracked return path can never be a redirect off the site: the
    // attempt is detached and wires the destination straight to the runner.
    let hijacked = oidc_login_attempt(&harness, ADMIN_USERNAME, Some("//evil.example"))
        .await
        .expect("admin login attempt with a hostile return path");
    assert_eq!(
        hijacked.location.as_deref(),
        Some("/"),
        "off-site return paths fall back to the console"
    );
}

#[tokio::test]
async fn oidc_admin_login_mints_a_session_and_logout_ends_it() {
    let harness = TestRunner::spawn(
        5,
        &lifecycle_server_toml(),
        "fake-server.sh",
        FAKE_SERVER_SCRIPT,
    )
    .expect("spawn harness");
    wait_until_listening(harness.port)
        .await
        .expect("runner did not come up");

    // A completed login marks the browser: the login page auto-redirects
    // it into the next login, so the admin never sees one.
    let attempt = oidc_login_attempt(&harness, ADMIN_USERNAME, None)
        .await
        .expect("admin login attempt");
    assert_eq!(attempt.status, 303, "login succeeded");
    assert!(
        attempt
            .set_cookies
            .iter()
            .any(|cookie| cookie.starts_with("was_admin=1")),
        "a completed admin login must mark the browser"
    );
    let mut cookie = cookie_from_set_cookie(&attempt.set_cookies, "auth")
        .expect("the oidc callback carries no session cookie");

    let (status, body) = me(harness.port, &mut cookie).await.expect("me as admin");
    assert_eq!(status, 200, "me as admin");
    assert_eq!(
        body,
        json!({ "id": 0, "name": ADMIN_USERNAME, "is_admin": true }),
        "the admin is user 0, named after the identity claim"
    );
    let auth_config = http_request(
        harness.port,
        reqwest::Method::GET,
        "/api/auth/config",
        None,
        Some(("was_admin", "1")),
    )
    .await
    .expect("auth config with marker");
    assert_eq!(
        auth_config.body, r#"{"bot_username":null,"oidc":true,"was_admin":true}"#,
        "the marked browser gets told it may auto-redirect"
    );

    // Logout ends the session and unmarks the browser: logging out must
    // actually log out, even against a provider that would auto-approve.
    let status = logout(harness.port, &mut cookie).await.expect("logout");
    assert_eq!(status, 200, "logout status");
    let (status, _) = me(harness.port, &mut cookie)
        .await
        .expect("me after logout");
    assert_eq!(status, 401, "the logged-out session must be rejected");
}

#[tokio::test]
async fn oidc_rejects_identities_that_are_not_the_admin() {
    let harness = TestRunner::spawn(
        5,
        &lifecycle_server_toml(),
        "fake-server.sh",
        FAKE_SERVER_SCRIPT,
    )
    .expect("spawn harness");
    wait_until_listening(harness.port)
        .await
        .expect("runner did not come up");

    // The provider authenticates the tailnet member fine, but the runner
    // only accepts the configured admin.
    let attempt = oidc_login_attempt(&harness, "mallory", None)
        .await
        .expect("login attempt as mallory");
    assert_eq!(attempt.status, 403, "non-admin identity must be refused");
    assert!(
        !attempt
            .set_cookies
            .iter()
            .any(|cookie| cookie.starts_with("auth=")),
        "a refused login must not mint a session"
    );

    // And no session exists afterwards.
    let response = http_request(
        harness.port,
        reqwest::Method::GET,
        "/api/auth/me",
        None,
        None,
    )
    .await
    .expect("me without a session");
    assert_eq!(response.status, 401, "no session was minted");
}

#[tokio::test]
async fn oidc_login_state_is_one_shot() {
    let harness = TestRunner::spawn(
        5,
        &lifecycle_server_toml(),
        "fake-server.sh",
        FAKE_SERVER_SCRIPT,
    )
    .expect("spawn harness");
    wait_until_listening(harness.port)
        .await
        .expect("runner did not come up");

    // Complete one login, capturing the pieces a replay would need.
    let start = http_request(
        harness.port,
        reqwest::Method::GET,
        "/api/auth/oidc/login",
        None,
        None,
    )
    .await
    .expect("start an oidc login");
    assert_eq!(start.status, 303, "login start should redirect");
    let location = start.location.expect("login redirect location");
    let query = location
        .split_once('?')
        .map_or(String::new(), |(_, query)| query.to_string());
    let query = query.as_str();
    let state_token = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("state="))
        .expect("state in the authorize url")
        .to_string();
    let state_cookie =
        cookie_from_set_cookie(&start.set_cookies, "oidc_login").expect("state cookie");

    // Stage the provider and complete the flow once.
    {
        let params = params_of(&location);
        stage_idp(
            &harness.idp.state,
            params.get("code_challenge").cloned(),
            params.get("redirect_uri").cloned(),
            ADMIN_USERNAME,
            false,
            false,
        );
    }
    let first = http_request(
        harness.port,
        reqwest::Method::GET,
        &format!("/api/auth/oidc/callback?code={OIDC_CODE}&state={state_token}"),
        None,
        Some(("oidc_login", state_cookie.as_str())),
    )
    .await
    .expect("first callback");
    assert_eq!(first.status, 303, "the first callback must succeed");

    // The replay: same cookie, same code, same state. The one-shot row is
    // gone, so the runner must refuse.
    let replay = http_request(
        harness.port,
        reqwest::Method::GET,
        &format!("/api/auth/oidc/callback?code={OIDC_CODE}&state={state_token}"),
        None,
        Some(("oidc_login", state_cookie.as_str())),
    )
    .await
    .expect("replayed callback");
    assert_eq!(replay.status, 400, "a replayed login must be refused");
}

#[tokio::test]
async fn oidc_exchange_failures_surface_as_bad_gateway() {
    let harness = TestRunner::spawn(
        5,
        &lifecycle_server_toml(),
        "fake-server.sh",
        FAKE_SERVER_SCRIPT,
    )
    .expect("spawn harness");
    wait_until_listening(harness.port)
        .await
        .expect("runner did not come up");

    let start = http_request(
        harness.port,
        reqwest::Method::GET,
        "/api/auth/oidc/login",
        None,
        None,
    )
    .await
    .expect("start an oidc login");
    let location = start.location.expect("login redirect location");
    let params = params_of(&location);
    let state_token = params.get("state").cloned().expect("state");
    let state_cookie =
        cookie_from_set_cookie(&start.set_cookies, "oidc_login").expect("state cookie");

    {
        let params = params_of(&location);
        stage_idp(
            &harness.idp.state,
            params.get("code_challenge").cloned(),
            params.get("redirect_uri").cloned(),
            ADMIN_USERNAME,
            false,
            true,
        );
    }

    let attempt = http_request(
        harness.port,
        reqwest::Method::GET,
        &format!("/api/auth/oidc/callback?code={OIDC_CODE}&state={state_token}"),
        None,
        Some(("oidc_login", state_cookie.as_str())),
    )
    .await
    .expect("callback with a failing provider");
    assert_eq!(
        attempt.status, 502,
        "a provider-side exchange failure must surface as bad gateway"
    );
}

#[tokio::test]
async fn half_configured_oidc_env_refuses_to_start() {
    let idp = MockIdp::new(ADMIN_USERNAME).expect("mock idp");
    let dir = tempfile::TempDir::new().expect("temp dir");
    std::fs::write(
        dir.path().join("config.toml"),
        "port = 0\nserver_name = \"x\"\ncommand = \"true\"\n",
    )
    .expect("write config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_game-server-runner"))
        .current_dir(dir.path())
        .env("CONFIG_PATH", dir.path().join("config.toml"))
        .env("OIDC_ISSUER", idp.issuer())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn runner with a half configured oidc env");
    let status = wait_for_exit(&mut child, Duration::from_secs(10))
        .await
        .expect("wait for exit")
        .expect("runner should exit on a half configured oidc env");
    assert!(
        !status.success(),
        "a half configured oidc env must refuse to start"
    );
    let mut stderr = String::new();
    if let Some(pipe) = child.stderr.take() {
        let mut pipe = pipe;
        pipe.read_to_string(&mut stderr).await.expect("read stderr");
    }
    assert!(
        stderr.contains("half configured"),
        "the error should say the oidc env is half configured: {stderr}"
    );
}

/// Parse the query parameters of a url into a map.
fn params_of(url: &str) -> BTreeMap<String, String> {
    let query = url.split_once('?').map_or("", |(_, query)| query);
    let mut params = BTreeMap::new();
    for pair in query.split('&') {
        if let Some((name, value)) = pair.split_once('=') {
            params.insert(percent_decode(name), percent_decode(value));
        }
    }
    params
}

// --- telegram login ---------------------------------------------------------

#[tokio::test]
async fn telegram_unknown_account_queues_and_approval_registers_it() {
    let harness = TestRunner::spawn_with_telegram(
        5,
        &lifecycle_server_toml(),
        "fake-server.sh",
        FAKE_SERVER_SCRIPT,
    )
    .expect("spawn harness");
    wait_until_listening(harness.port)
        .await
        .expect("runner did not come up");

    // The login page config advertises both login methods.
    let response = http_request(
        harness.port,
        reqwest::Method::GET,
        "/api/auth/config",
        None,
        None,
    )
    .await
    .expect("auth config");
    assert_eq!(response.status, 200, "auth config status");
    let config: Value = serde_json::from_str(&response.body).expect("config body");
    assert_eq!(config["bot_username"], json!(TELEGRAM_BOT_USERNAME));
    assert_eq!(config["oidc"], json!(true));
    assert_eq!(config["was_admin"], json!(false), "fresh browser unmarked");

    // Unknown account: queued, not logged in.
    let response = telegram_login(harness.port, telegram_payload(42, "alice"))
        .await
        .expect("telegram login as unknown alice");
    assert_eq!(response.status, 202, "unknown accounts get queued");
    let body: Value = serde_json::from_str(&response.body).expect("queueing body");
    assert_eq!(body["status"], json!("pending"), "queueing status");

    // A second request while queued is a conflict.
    let response = telegram_login(harness.port, telegram_payload(42, "alice"))
        .await
        .expect("second telegram login while queued");
    assert_eq!(response.status, 409, "duplicate requests conflict");
    assert!(
        response.set_cookies.is_empty(),
        "queueing must not mint a session"
    );

    // The admin sees the request and approves it.
    let mut admin_cookie = admin_session(&harness).await.expect("admin session");
    let (status, pending) = admin_list_pending(harness.port, &mut admin_cookie)
        .await
        .expect("pending list");
    assert_eq!(status, 200, "pending list status");
    let entry = pending
        .as_array()
        .and_then(|entries| entries.first())
        .cloned()
        .expect("alice should be queued");
    assert_eq!(entry["telegram_id"], json!(42), "queued telegram id");
    assert_eq!(entry["username"], json!("alice"), "queued username");

    let status = admin_pending_action(harness.port, &mut admin_cookie, 42, "approve")
        .await
        .expect("approve alice");
    assert_eq!(status, 201, "approve status");

    // Now the telegram login mints a real session.
    let response = telegram_login(harness.port, telegram_payload(42, "alice"))
        .await
        .expect("telegram login as approved alice");
    assert_eq!(response.status, 201, "approved accounts get a session");
    let mut alice_cookie = cookie_from_set_cookie(&response.set_cookies, "auth")
        .expect("session cookie from telegram login");
    let (status, body) = me(harness.port, &mut alice_cookie)
        .await
        .expect("me as alice");
    assert_eq!(status, 200, "me as alice");
    assert_ne!(body["id"], json!(0), "alice is not the admin");
    assert_eq!(body["is_admin"], json!(false), "alice gets no admin gate");
    assert_eq!(body["name"], json!("alice"), "alice name from the claim");
}

#[tokio::test]
async fn telegram_denied_requests_can_queue_again() {
    let harness = TestRunner::spawn_with_telegram(
        5,
        &lifecycle_server_toml(),
        "fake-server.sh",
        FAKE_SERVER_SCRIPT,
    )
    .expect("spawn harness");
    wait_until_listening(harness.port)
        .await
        .expect("runner did not come up");
    let mut admin_cookie = admin_session(&harness).await.expect("admin session");

    let response = telegram_login(harness.port, telegram_payload(7, "bob"))
        .await
        .expect("telegram login as unknown bob");
    assert_eq!(response.status, 202, "bob gets queued");

    let status = admin_pending_action(harness.port, &mut admin_cookie, 7, "deny")
        .await
        .expect("deny bob");
    assert_eq!(status, 200, "deny status");
    let (status, pending) = admin_list_pending(harness.port, &mut admin_cookie)
        .await
        .expect("pending list after deny");
    assert_eq!(status, 200, "pending list status");
    assert_eq!(
        pending.as_array().map(Vec::len),
        Some(0),
        "the denied request is gone"
    );

    // Denial is not a ban: bob may ask again, landing as a fresh request.
    let response = telegram_login(harness.port, telegram_payload(7, "bob"))
        .await
        .expect("telegram login after denial");
    assert_eq!(response.status, 202, "bob can queue again after a denial");
}

#[tokio::test]
async fn telegram_rejects_forged_and_stale_payloads() {
    let harness = TestRunner::spawn_with_telegram(
        5,
        &lifecycle_server_toml(),
        "fake-server.sh",
        FAKE_SERVER_SCRIPT,
    )
    .expect("spawn harness");
    wait_until_listening(harness.port)
        .await
        .expect("runner did not come up");

    // A tampered payload breaks the signature.
    let mut forged = telegram_payload(13, "mallory");
    forged["username"] = json!("admin");
    let response = telegram_login(harness.port, forged)
        .await
        .expect("forged telegram login");
    assert_eq!(response.status, 401, "tampered payloads must be refused");

    // A payload older than the freshness window is stale.
    let mut fields = serde_json::Map::new();
    fields.insert(String::from("id"), Value::from(13));
    fields.insert(String::from("username"), Value::from("mallory"));
    fields.insert(
        String::from("auth_date"),
        Value::from(unix_now().expect("unix time") - 3600),
    );
    let stale = signed_telegram_payload(fields);
    let response = telegram_login(harness.port, stale)
        .await
        .expect("stale telegram login");
    assert_eq!(response.status, 400, "stale payloads must be refused");

    // A payload without a hash is not a widget payload at all.
    let unsigned = json!({ "id": 13, "username": "mallory", "auth_date": 1 });
    let response = telegram_login(harness.port, unsigned)
        .await
        .expect("unsigned telegram login");
    assert_eq!(response.status, 401, "unsigned payloads must be refused");

    // Nothing was queued for the forger.
    let mut admin_cookie = admin_session(&harness).await.expect("admin session");
    let (status, pending) = admin_list_pending(harness.port, &mut admin_cookie)
        .await
        .expect("pending list");
    assert_eq!(status, 200, "pending list status");
    assert_eq!(
        pending.as_array().map(Vec::len),
        Some(0),
        "rejected payloads must not queue"
    );
}

#[tokio::test]
async fn telegram_login_is_disabled_without_a_bot_token() {
    let harness = TestRunner::spawn(
        5,
        &lifecycle_server_toml(),
        "fake-server.sh",
        FAKE_SERVER_SCRIPT,
    )
    .expect("spawn harness");
    wait_until_listening(harness.port)
        .await
        .expect("runner did not come up");

    let response = http_request(
        harness.port,
        reqwest::Method::GET,
        "/api/auth/config",
        None,
        None,
    )
    .await
    .expect("auth config");
    let config: Value = serde_json::from_str(&response.body).expect("config body");
    assert_eq!(config["bot_username"], json!(null), "no bot, no widget");
    assert_eq!(
        config["oidc"],
        json!(true),
        "oidc is always configured here"
    );
    assert_eq!(
        config["was_admin"],
        json!(false),
        "no marker, no auto-redirect"
    );

    let response = telegram_login(harness.port, telegram_payload(1, "whoever"))
        .await
        .expect("telegram login while disabled");
    assert_eq!(response.status, 404, "telegram login must be disabled");
}

#[tokio::test]
async fn banning_kicks_sessions_and_locks_the_account() {
    let harness = TestRunner::spawn_with_telegram(
        5,
        &lifecycle_server_toml(),
        "fake-server.sh",
        FAKE_SERVER_SCRIPT,
    )
    .expect("spawn harness");
    wait_until_listening(harness.port)
        .await
        .expect("runner did not come up");
    let mut admin_cookie = admin_session(&harness).await.expect("admin session");

    // Register alice through the queue, then log her in.
    let response = telegram_login(harness.port, telegram_payload(42, "alice"))
        .await
        .expect("queue alice");
    assert_eq!(response.status, 202, "alice queued");
    let status = admin_pending_action(harness.port, &mut admin_cookie, 42, "approve")
        .await
        .expect("approve alice");
    assert_eq!(status, 201, "alice approved");
    let response = telegram_login(harness.port, telegram_payload(42, "alice"))
        .await
        .expect("alice logs in");
    assert_eq!(response.status, 201, "alice session");
    let mut alice_cookie =
        cookie_from_set_cookie(&response.set_cookies, "auth").expect("alice session cookie");
    let (status, _) = me(harness.port, &mut alice_cookie)
        .await
        .expect("me as alice");
    assert_eq!(status, 200, "alice is in");

    // Banning wipes her session right away.
    let status = admin_ban_action(harness.port, &mut admin_cookie, 0, "ban")
        .await
        .expect("try to ban the admin");
    assert_eq!(status, 400, "the admin cannot be banned");
    let alice_id = alice_user_id(&harness).await.expect("alice id");
    let status = admin_ban_action(harness.port, &mut admin_cookie, alice_id, "ban")
        .await
        .expect("ban alice");
    assert_eq!(status, 200, "ban status");
    let (status, _) = me(harness.port, &mut alice_cookie)
        .await
        .expect("me as banned alice");
    assert_eq!(status, 401, "the ban must kill the live session");

    // And she cannot log back in: the account is recognized but refused.
    let response = telegram_login(harness.port, telegram_payload(42, "alice"))
        .await
        .expect("telegram login as banned alice");
    assert_eq!(response.status, 403, "banned accounts are refused");

    // Unban: the telegram binding is intact, so she is right back in.
    let status = admin_ban_action(harness.port, &mut admin_cookie, alice_id, "unban")
        .await
        .expect("unban alice");
    assert_eq!(status, 200, "unban status");
    let response = telegram_login(harness.port, telegram_payload(42, "alice"))
        .await
        .expect("telegram login after unban");
    assert_eq!(response.status, 201, "unbanned accounts can log in again");
}

/// The user id of the freshly registered alice, read from the database.
async fn alice_user_id(harness: &TestRunner) -> Result<i64, String> {
    let db = open_db(&harness.db_path).await?;
    sqlx::query_scalar("SELECT id FROM users WHERE telegram_id = 42")
        .fetch_one(&db)
        .await
        .map_err(|err| format!("alice should exist: {err}"))
}

#[tokio::test]
async fn expired_pending_requests_become_invisible() {
    let harness = TestRunner::spawn_with_telegram(
        5,
        &lifecycle_server_toml(),
        "fake-server.sh",
        FAKE_SERVER_SCRIPT,
    )
    .expect("spawn harness");
    wait_until_listening(harness.port)
        .await
        .expect("runner did not come up");
    let mut admin_cookie = admin_session(&harness).await.expect("admin session");

    let response = telegram_login(harness.port, telegram_payload(5, "carol"))
        .await
        .expect("queue carol");
    assert_eq!(response.status, 202, "carol queued");

    // Age the request past the one hour window directly in the database.
    let db = open_db(&harness.db_path).await.expect("open db");
    sqlx::query("UPDATE pending_users SET created = created - 7200")
        .execute(&db)
        .await
        .expect("age the pending request");

    let (status, pending) = admin_list_pending(harness.port, &mut admin_cookie)
        .await
        .expect("pending list");
    assert_eq!(status, 200, "pending list status");
    assert_eq!(
        pending.as_array().map(Vec::len),
        Some(0),
        "expired requests must not be listed"
    );
    let status = admin_pending_action(harness.port, &mut admin_cookie, 5, "approve")
        .await
        .expect("approve an expired request");
    assert_eq!(status, 404, "expired requests cannot be approved");

    // The cleanup sweep removes the row entirely; carol can simply queue
    // again in the meantime.
    let response = telegram_login(harness.port, telegram_payload(5, "carol"))
        .await
        .expect("carol queues again");
    assert_eq!(
        response.status, 202,
        "a fresh request replaces the stale one"
    );
}
