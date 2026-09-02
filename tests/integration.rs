//! Integration tests that drive the real `game-server-runner` binary with a
//! fake game server script, speak the websocket protocol to it, and exercise
//! the M2 auth flows end to end.
//!
//! Cookie handling note: the runner sets `Secure` cookies, and reqwest's
//! cookie jar would refuse to store or resend them over plain http. The
//! tests therefore use no jar: each helper reads the token out of the
//! `Set-Cookie` response header and sends it back manually as
//! `Cookie: auth=<value>` (and on the websocket upgrade request). This is
//! deterministic and mirrors exactly what the browser frontend does.

use std::fmt::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use sha3::{Digest, Sha3_256};
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
/// Prefix of the stderr log line carrying the bootstrap invitation token.
const ADMIN_TOKEN_PREFIX: &str = "admin invitation token: ";
/// Sessions slide forward by this many seconds on every authenticated
/// request; the rotation test needs the clock to move at least one second.
const ROTATION_SLEEP: Duration = Duration::from_millis(1100);

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
}

impl TestRunner {
    /// Write the config files and spawn the real binary in the temp dir,
    /// with stderr captured into a shared buffer the tests can grep.
    fn spawn(
        minutes_before_stop: u64,
        server_toml: &str,
        script_name: &str,
        server_script: &str,
    ) -> Result<Self, String> {
        Self::spawn_with_config(
            minutes_before_stop,
            server_toml,
            script_name,
            server_script,
            None,
        )
    }

    /// Like [`TestRunner::spawn`], but with `restic_repo` set a fake restic
    /// binary is installed and restic backups are enabled with that repo
    /// marker. Telegram stays disabled, the default.
    fn spawn_with_config(
        minutes_before_stop: u64,
        server_toml: &str,
        script_name: &str,
        server_script: &str,
        restic_repo: Option<&str>,
    ) -> Result<Self, String> {
        let port = next_port();
        let dir = TempDir::new().map_err(|err| format!("create temp dir: {err}"))?;
        let mut config = format!(
            "db_path = 'test.db'\n\
             port = {port}\n\
             connect_url = 'localhost:25565'\n\
             server_dir = 'server'\n\
             minutes_before_stop = {minutes_before_stop}\n\
             log_level = 'debug'\n"
        );
        if let Some(repo) = restic_repo {
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

        let mut child = Command::new(env!("CARGO_BIN_EXE_game-server-runner"))
            .current_dir(dir.path())
            .env("CONFIG_PATH", dir.path().join("config.toml"))
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

    /// Wait for the startup log line `admin invitation token: <b64>` and
    /// return the token.
    fn wait_for_admin_token(&self) -> Result<String, String> {
        let deadline = Instant::now()
            .checked_add(STARTUP_TIMEOUT)
            .unwrap_or_else(Instant::now);
        loop {
            let text = self.stderr_text();
            if let Some((_prefix, rest)) = text.split_once(ADMIN_TOKEN_PREFIX) {
                let line = rest.lines().next().unwrap_or_default();
                return Ok(line.trim().to_string());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "no admin invitation token on stderr within {STARTUP_TIMEOUT:?}; \
                     stderr so far: {}",
                    self.stderr_text()
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
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
    set_cookie: Option<String>,
    body: String,
}

/// One JSON HTTP request with an optional manual `Cookie: auth=<value>`
/// header. Cookies are never stored in a jar; see the module comment.
async fn http_request(
    port: u16,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
    cookie: Option<&str>,
) -> Result<HttpResponse, String> {
    let client = reqwest::Client::builder()
        .timeout(MESSAGE_TIMEOUT)
        .build()
        .map_err(|err| format!("build http client: {err}"))?;
    let mut request = client.request(method, format!("http://127.0.0.1:{port}{path}"));
    if let Some(body) = body {
        request = request.json(&body);
    }
    if let Some(cookie) = cookie {
        request = request.header(reqwest::header::COOKIE, format!("auth={cookie}"));
    }
    let response = request
        .send()
        .await
        .map_err(|err| format!("http request to {path}: {err}"))?;
    let status = response.status().as_u16();
    let set_cookie = response
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let body = response
        .text()
        .await
        .map_err(|err| format!("http body of {path}: {err}"))?;
    Ok(HttpResponse {
        status,
        set_cookie,
        body,
    })
}

/// Extract the session token from an `auth=...; attributes` Set-Cookie
/// header value.
fn cookie_from_set_cookie(set_cookie: Option<String>) -> Option<String> {
    let raw = set_cookie?;
    let value = raw.strip_prefix("auth=")?;
    let end = value.find(';').unwrap_or(value.len());
    value.get(..end).map(str::to_string)
}

/// Register a fresh user; returns the new session cookie.
async fn register(port: u16, invitation_token: &str, name: &str) -> Result<String, String> {
    let response = http_request(
        port,
        reqwest::Method::POST,
        "/api/auth/register",
        Some(json!({ "invitation_token": invitation_token, "name": name })),
        None,
    )
    .await?;
    if response.status != 201 {
        return Err(format!(
            "register {name:?} failed: {} {}",
            response.status, response.body
        ));
    }
    cookie_from_set_cookie(response.set_cookie)
        .ok_or_else(|| String::from("register response carried no session cookie"))
}

/// Admin bootstrap: token from stderr, then register user 0 as "admin".
async fn admin_session(harness: &TestRunner) -> Result<String, String> {
    let token = harness.wait_for_admin_token()?;
    register(harness.port, &token, "admin").await
}

/// Authenticated GET /api/auth/me. Rotates `cookie` in place when the
/// response carries a new one.
async fn me(port: u16, cookie: &mut String) -> Result<(u16, Value), String> {
    let response = http_request(
        port,
        reqwest::Method::GET,
        "/api/auth/me",
        None,
        Some(cookie.as_str()),
    )
    .await?;
    if let Some(updated) = cookie_from_set_cookie(response.set_cookie) {
        *cookie = updated;
    }
    let body: Value = serde_json::from_str(&response.body).unwrap_or(Value::Null);
    Ok((response.status, body))
}

/// Authenticated POST /api/auth/invite; returns the invitation token.
async fn invite(port: u16, admin_cookie: &mut String) -> Result<String, String> {
    let response = http_request(
        port,
        reqwest::Method::POST,
        "/api/auth/invite",
        None,
        Some(admin_cookie.as_str()),
    )
    .await?;
    if let Some(updated) = cookie_from_set_cookie(response.set_cookie) {
        *admin_cookie = updated;
    }
    if response.status != 201 {
        return Err(format!(
            "invite failed: {} {}",
            response.status, response.body
        ));
    }
    let body: Value = serde_json::from_str(&response.body)
        .map_err(|err| format!("invite body is not json: {err}"))?;
    body.get("invitation_token")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("invite body has no invitation_token: {}", response.body))
}

/// Authenticated POST /api/auth/addDevice; returns the login token.
async fn add_device(port: u16, cookie: &mut String) -> Result<String, String> {
    let response = http_request(
        port,
        reqwest::Method::POST,
        "/api/auth/addDevice",
        None,
        Some(cookie.as_str()),
    )
    .await?;
    if let Some(updated) = cookie_from_set_cookie(response.set_cookie) {
        *cookie = updated;
    }
    if response.status != 201 {
        return Err(format!(
            "addDevice failed: {} {}",
            response.status, response.body
        ));
    }
    let body: Value = serde_json::from_str(&response.body)
        .map_err(|err| format!("addDevice body is not json: {err}"))?;
    body.get("login_token")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("addDevice body has no login_token: {}", response.body))
}

/// Unauthenticated POST /api/auth/login from a clean client; returns the
/// status and the Set-Cookie header value, if any.
async fn login(port: u16, login_token: &str) -> Result<(u16, Option<String>), String> {
    let response = http_request(
        port,
        reqwest::Method::POST,
        "/api/auth/login",
        Some(json!({ "login_token": login_token })),
        None,
    )
    .await?;
    Ok((response.status, response.set_cookie))
}

/// Authenticated DELETE /api/auth/logout; rotates `cookie` in place and
/// returns the status.
async fn logout(port: u16, cookie: &mut String) -> Result<u16, String> {
    let response = http_request(
        port,
        reqwest::Method::DELETE,
        "/api/auth/logout",
        None,
        Some(cookie.as_str()),
    )
    .await?;
    if let Some(updated) = cookie_from_set_cookie(response.set_cookie) {
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
async fn register_rejects_missing_malformed_and_expired_invitation_tokens() {
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
    harness
        .wait_for_admin_token()
        .expect("admin token on stderr");

    // Well-formed but unknown token: 404.
    let unknown = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let response = http_request(
        harness.port,
        reqwest::Method::POST,
        "/api/auth/register",
        Some(json!({ "invitation_token": unknown, "name": "whoever" })),
        None,
    )
    .await
    .expect("register with unknown token");
    assert_eq!(response.status, 404, "unknown token: {}", response.body);

    // Malformed base64: 400.
    let response = http_request(
        harness.port,
        reqwest::Method::POST,
        "/api/auth/register",
        Some(json!({ "invitation_token": "!!! not base64", "name": "whoever" })),
        None,
    )
    .await
    .expect("register with malformed token");
    assert_eq!(response.status, 400, "malformed token: {}", response.body);

    // Expired token, planted straight into the database: 401.
    let db = open_db(&harness.db_path).await.expect("open db");
    let raw = rand::random::<[u8; 32]>();
    let expired_token = URL_SAFE_NO_PAD.encode(raw);
    let hash: [u8; 32] = Sha3_256::digest(raw).into();
    let now = unix_now().expect("unix time");
    sqlx::query(
        "INSERT INTO tokens (token_hash, kind, user_id, expires) VALUES (?, 'invitation', 0, ?)",
    )
    .bind(&hash[..])
    .bind(now - 10)
    .execute(&db)
    .await
    .expect("insert expired invitation token");
    let response = http_request(
        harness.port,
        reqwest::Method::POST,
        "/api/auth/register",
        Some(json!({ "invitation_token": expired_token, "name": "whoever" })),
        None,
    )
    .await
    .expect("register with expired token");
    assert_eq!(response.status, 401, "expired token: {}", response.body);
}

#[tokio::test]
async fn admin_invite_register_login_logout_flow() {
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

    // Bootstrap token from stderr -> register the admin (user 0).
    let admin_token = harness.wait_for_admin_token().expect("admin token");
    let mut admin_cookie = register(harness.port, &admin_token, "admin")
        .await
        .expect("register admin");
    let (status, body) = me(harness.port, &mut admin_cookie)
        .await
        .expect("me as admin");
    assert_eq!(status, 200, "me as admin");
    assert_eq!(body, json!({ "id": 0, "name": "admin" }), "admin identity");

    // Invite a second user and register them as "bob".
    let invitation = invite(harness.port, &mut admin_cookie)
        .await
        .expect("invite by admin");
    let mut bob_cookie = register(harness.port, &invitation, "bob")
        .await
        .expect("register bob");
    let (status, body) = me(harness.port, &mut bob_cookie).await.expect("me as bob");
    assert_eq!(status, 200, "me as bob");
    let bob_id = body["id"].as_i64().expect("bob id is a number");
    assert_ne!(bob_id, 0, "bob must not be the admin");
    assert_eq!(body["name"], json!("bob"), "bob name");

    // Non-admins cannot invite. The 403 still rotates the session, so the
    // test must pick up the new cookie from the response.
    let response = http_request(
        harness.port,
        reqwest::Method::POST,
        "/api/auth/invite",
        None,
        Some(bob_cookie.as_str()),
    )
    .await
    .expect("invite as bob");
    assert_eq!(response.status, 403, "bob inviting should be forbidden");
    if let Some(updated) = cookie_from_set_cookie(response.set_cookie) {
        bob_cookie = updated;
    }

    // Mint a login token and use it from a clean client.
    let login_token = add_device(harness.port, &mut bob_cookie)
        .await
        .expect("addDevice as bob");
    let (status, set_cookie) = login(harness.port, &login_token)
        .await
        .expect("login with the device token");
    assert_eq!(status, 201, "login status");
    let mut device_cookie =
        cookie_from_set_cookie(set_cookie).expect("login response carries a session cookie");
    let (status, body) = me(harness.port, &mut device_cookie)
        .await
        .expect("me on the new device");
    assert_eq!(status, 200, "me after login");
    assert_eq!(body["id"], json!(bob_id), "same user on the new device");

    // Logout ends the session.
    let status = logout(harness.port, &mut device_cookie)
        .await
        .expect("logout");
    assert_eq!(status, 200, "logout status");
    let (status, _) = me(harness.port, &mut device_cookie)
        .await
        .expect("me after logout");
    assert_eq!(status, 401, "the logged-out session must be rejected");
}

#[tokio::test]
async fn registering_existing_name_claims_the_user() {
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
    let mut admin_cookie = admin_session(&harness).await.expect("admin session");

    let first_invitation = invite(harness.port, &mut admin_cookie)
        .await
        .expect("first invite");
    let mut bob_cookie = register(harness.port, &first_invitation, "bob")
        .await
        .expect("register bob");
    let (_, body) = me(harness.port, &mut bob_cookie).await.expect("me as bob");
    let bob_id = body["id"].as_i64().expect("bob id is a number");

    // A fresh invitation registering the same name must claim bob's user.
    let second_invitation = invite(harness.port, &mut admin_cookie)
        .await
        .expect("second invite");
    let mut reborn_cookie = register(harness.port, &second_invitation, "bob")
        .await
        .expect("register bob again");
    let (status, body) = me(harness.port, &mut reborn_cookie)
        .await
        .expect("me as reclaimed bob");
    assert_eq!(status, 200, "reclaimed me");
    assert_eq!(
        body["id"],
        json!(bob_id),
        "the invitation must claim the existing bob, not create a new user"
    );

    // No orphaned placeholder users may remain.
    let db = open_db(&harness.db_path).await.expect("open db");
    let null_named: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE name IS NULL")
        .fetch_one(&db)
        .await
        .expect("count null-named users");
    assert_eq!(null_named, 0, "no NULL-named orphan rows may remain");
    let bobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE name = 'bob'")
        .fetch_one(&db)
        .await
        .expect("count bob users");
    assert_eq!(bobs, 1, "bob exists exactly once");
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
        Some(cookie.as_str()),
    )
    .await
    .expect("me with the original cookie");
    assert_eq!(response.status, 200, "me with the original cookie");
    let rotated = cookie_from_set_cookie(response.set_cookie)
        .expect("the response must rotate the session cookie");
    assert_ne!(rotated, cookie, "rotation must produce a new token");

    // Replaying the old cookie must fail: the session moved on.
    let replay = http_request(
        harness.port,
        reqwest::Method::GET,
        "/api/auth/me",
        None,
        Some(cookie.as_str()),
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
