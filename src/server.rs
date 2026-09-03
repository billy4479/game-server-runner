//! The server runner: process lifecycle, output pipes and log buffer,
//! websocket broadcast feeds, console forwarding, graceful stop with
//! escalation, and auto-stop scheduling.

use std::io;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::broadcast;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use crate::clock::unix_now;
use crate::config::{Config, ServerConfig, StopPayload, StopSettings};
use crate::players::{PlayerEvent, PlayerTracker};
use crate::restic;
use crate::signals;
use crate::state::ServerState;
use crate::telegram;

/// Broadcast capacity for state updates.
const STATE_CHANNEL_CAPACITY: usize = 64;
/// Broadcast capacity for chat lines.
const CHAT_CHANNEL_CAPACITY: usize = 256;
/// Buffer for control messages to the supervisor.
const CONTROL_CHANNEL_CAPACITY: usize = 4;
/// Buffer for console lines on their way to the server stdin.
const CONSOLE_CHANNEL_CAPACITY: usize = 128;
/// How long to wait for the output readers to drain once the child exited.
const READER_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Sentinel for "no auto stop scheduled": Unix seconds of `i64::MAX`.
const NO_AUTO_STOP: i64 = i64::MAX;

/// Request sent to the supervisor task.
#[derive(Debug)]
enum Control {
    /// Run the graceful stop action, wait out the grace period, escalate.
    GracefulStop,
}

/// Why the first supervision phase ended.
#[derive(Debug)]
enum Supervision {
    /// The child exited on its own (or after a previous stop).
    Exited(io::Result<std::process::ExitStatus>),
    /// A graceful stop was requested.
    StopRequested,
}

/// Mutable state shared between tasks, guarded by a plain mutex; no await
/// ever happens while a guard is held.
struct Shared {
    is_running: bool,
    auto_stop_time: i64,
    log: String,
}

/// Per-run channel senders kept by the runner; `None` between runs.
struct Channels {
    control: Option<mpsc::Sender<Control>>,
    console: Option<mpsc::Sender<String>>,
}

/// Shared handle for the whole application: web routes, the supervisor, the
/// console forwarder and the shutdown path all talk to the runner through it.
pub struct Runner {
    global: Arc<Config>,
    server: ServerConfig,
    players: PlayerTracker,
    shared: Mutex<Shared>,
    channels: Mutex<Channels>,
    supervisor: Mutex<Option<JoinHandle<()>>>,
    /// Excludes concurrent `start` calls so only one child can be spawned.
    start_lock: tokio::sync::Mutex<()>,
    state_tx: broadcast::Sender<Arc<ServerState>>,
    chat_tx: broadcast::Sender<String>,
    shutdown_tx: watch::Sender<()>,
    /// Set while a graceful stop is in flight so repeated requests are no-ops.
    stopping: AtomicBool,
    /// Bumped on every schedule and on every exit; a scheduled auto stop only
    /// fires if the generation is still current.
    auto_stop_generation: AtomicU64,
}

impl Runner {
    /// Assemble the runner. The per-server config must already be validated.
    #[must_use]
    pub fn new(global: Arc<Config>, server: ServerConfig) -> Self {
        let (state_tx, _) = broadcast::channel(STATE_CHANNEL_CAPACITY);
        let (chat_tx, _) = broadcast::channel(CHAT_CHANNEL_CAPACITY);
        let (shutdown_tx, _) = watch::channel(());
        Self {
            global,
            players: PlayerTracker::new(server.players.clone()),
            server,
            shared: Mutex::new(Shared {
                is_running: false,
                auto_stop_time: NO_AUTO_STOP,
                log: String::new(),
            }),
            channels: Mutex::new(Channels {
                control: None,
                console: None,
            }),
            supervisor: Mutex::new(None),
            start_lock: tokio::sync::Mutex::new(()),
            state_tx,
            chat_tx,
            shutdown_tx,
            stopping: AtomicBool::new(false),
            auto_stop_generation: AtomicU64::new(0),
        }
    }

    /// Start the game server process and spawn its supervisor.
    ///
    /// Starting an already running server is a no-op, mirroring mc-runner.
    ///
    /// # Errors
    /// Returns the spawn error if the process could not be started.
    pub async fn start(self: &Arc<Self>) -> io::Result<()> {
        let _start_guard = self.start_lock.lock().await;
        if self.is_running() {
            debug!("start requested but the server is already running");
            return Ok(());
        }
        self.stopping.store(false, Ordering::SeqCst);

        let mut command = Command::new(&self.server.command);
        command
            .args(&self.server.args)
            .current_dir(&self.global.server_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        debug!(
            command = %self.server.command,
            args = ?self.server.args,
            dir = %self.global.server_dir,
            "starting server"
        );
        let child = command.spawn()?;
        telegram::send_message(
            &self.global.telegram,
            &format!("Server {} starting...", self.server.server_name),
        );

        {
            let mut shared = self.lock_shared();
            shared.log.clear();
            shared.is_running = true;
            shared.auto_stop_time = NO_AUTO_STOP;
        }
        self.players.clear();

        let (control_tx, control_rx) = mpsc::channel(CONTROL_CHANNEL_CAPACITY);
        let (console_tx, console_rx) = mpsc::channel(CONSOLE_CHANNEL_CAPACITY);
        {
            let mut channels = self.lock_channels();
            channels.control = Some(control_tx);
            channels.console = Some(console_tx);
        }

        let supervisor = tokio::spawn(supervise(
            Arc::clone(self),
            child,
            self.server.stop.clone(),
            control_rx,
            console_rx,
        ));
        self.lock_supervisor().replace(supervisor);

        info!(server = %self.server.server_name, "server started");
        self.schedule_auto_stop();
        self.broadcast_state();
        Ok(())
    }

    /// Ask the supervisor to stop the server gracefully. No-op when the
    /// server is not running or a stop is already in flight.
    pub async fn stop(&self) {
        if !self.is_running() {
            debug!("stop requested but the server is not running");
            return;
        }
        if self.stopping.swap(true, Ordering::SeqCst) {
            debug!("a stop is already in progress");
            return;
        }
        let sender = {
            let channels = self.lock_channels();
            channels.control.clone()
        };
        let Some(sender) = sender else {
            debug!("no supervisor to stop; treating the request as done");
            self.stopping.store(false, Ordering::SeqCst);
            return;
        };
        if let Err(source) = sender.send(Control::GracefulStop).await {
            warn!("could not deliver the stop request to the supervisor: {source}");
            self.stopping.store(false, Ordering::SeqCst);
        }
    }

    /// Wait until the supervisor of the most recent start has finished, i.e.
    /// the child has fully exited and been cleaned up.
    pub async fn join_supervisor(&self) {
        let handle = self.lock_supervisor().take();
        if let Some(handle) = handle
            && let Err(source) = handle.await
        {
            warn!("supervisor task failed: {source}");
        }
    }

    /// Tell connected websocket clients that the runner is shutting down so
    /// they can close instead of keeping the connection open.
    pub fn notify_shutdown(&self) {
        // Err simply means no websocket is connected right now.
        match self.shutdown_tx.send(()) {
            Ok(()) | Err(_) => {}
        }
    }

    /// Subscribe to state updates.
    #[must_use]
    pub fn subscribe_state(&self) -> broadcast::Receiver<Arc<ServerState>> {
        self.state_tx.subscribe()
    }

    /// Subscribe to server output lines.
    #[must_use]
    pub fn subscribe_chat(&self) -> broadcast::Receiver<String> {
        self.chat_tx.subscribe()
    }

    /// Subscribe to the runner shutdown notification.
    #[must_use]
    pub fn subscribe_shutdown(&self) -> watch::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Current state snapshot.
    #[must_use]
    pub fn get_state(&self) -> Arc<ServerState> {
        let (is_running, auto_stop_time) = {
            let shared = self.lock_shared();
            (shared.is_running, shared.auto_stop_time)
        };
        Arc::new(ServerState {
            version: env!("CARGO_PKG_VERSION").to_string(),
            connect_url: self.global.connect_url.clone(),
            server_name: self.server.server_name.clone(),
            is_running,
            online_players: self.players.list(),
            auto_stop_time,
            bot_tag: String::new(),
        })
    }

    /// The whole output history of the current (or last) server session.
    #[must_use]
    pub fn chat_history(&self) -> String {
        self.lock_shared().log.clone()
    }

    /// Spawn the task that reads our own stdin and forwards lines to the
    /// server. Lines are dropped silently when no server is running or the
    /// channel is full, matching mc-runner.
    pub fn spawn_console_forwarder(runner: &Arc<Self>) {
        let runner = Arc::clone(runner);
        tokio::spawn(async move {
            let mut lines = BufReader::new(tokio::io::stdin()).lines();
            loop {
                match lines.next_line().await {
                    Ok(Some(line)) => {
                        let sender = {
                            let channels = runner.lock_channels();
                            channels.console.clone()
                        };
                        if let Some(sender) = sender {
                            // Dropped silently when there is no receiver or
                            // the buffer is full: mc-runner parity.
                            match sender.try_send(line) {
                                Ok(()) | Err(_) => {}
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(source) => {
                        debug!("console input ended: {source}");
                        break;
                    }
                }
            }
        });
    }

    fn is_running(&self) -> bool {
        self.lock_shared().is_running
    }

    fn lock_shared(&self) -> MutexGuard<'_, Shared> {
        self.shared.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn lock_channels(&self) -> MutexGuard<'_, Channels> {
        self.channels.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn lock_supervisor(&self) -> MutexGuard<'_, Option<JoinHandle<()>>> {
        self.supervisor
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn broadcast_state(&self) {
        let state = self.get_state();
        // Err means there is no websocket subscriber; that is normal.
        match self.state_tx.send(state) {
            Ok(_) | Err(_) => {}
        }
    }

    /// Handle one line of server output: append to the log buffer, broadcast
    /// it as chat, and track players. Broadcasts a new state when the player
    /// set changed and schedules the auto stop when the server became empty.
    fn on_output_line(self: &Arc<Self>, line: &str) {
        {
            let mut shared = self.lock_shared();
            shared.log.push_str(line);
            shared.log.push('\n');
        }
        // mc-runner appends the newline to live chat lines; the frontend
        // concatenates message data, so the terminator must be on the wire.
        match self.chat_tx.send(format!("{line}\n")) {
            Ok(_) | Err(_) => {}
        }

        if let Some(event) = self.players.parse_line(line) {
            match &event {
                PlayerEvent::Joined(name) => {
                    debug!(player = %name, "player joined");
                }
                PlayerEvent::Left(name) => {
                    debug!(player = %name, "player left");
                }
            }
            self.broadcast_state();
            if self.players.count() == 0 {
                self.schedule_auto_stop();
            }
        }
    }

    /// Schedule an auto stop `minutes_before_stop` minutes from now. Called
    /// on server start and whenever a leave empties the server. A scheduled
    /// stop only fires if no newer schedule or exit invalidated it.
    fn schedule_auto_stop(self: &Arc<Self>) {
        let minutes = self.global.minutes_before_stop;
        let delay_secs = minutes.saturating_mul(60);
        let generation = self
            .auto_stop_generation
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1);
        let stop_time = unix_now().saturating_add(i64::try_from(delay_secs).unwrap_or(i64::MAX));
        {
            let mut shared = self.lock_shared();
            shared.auto_stop_time = stop_time;
        }
        self.broadcast_state();
        debug!(minutes, generation, "auto stop scheduled");

        let runner = Arc::clone(self);
        tokio::spawn(async move {
            sleep(Duration::from_secs(delay_secs)).await;
            if runner.auto_stop_generation.load(Ordering::SeqCst) != generation {
                debug!(generation, "auto stop superseded");
            } else if runner.players.count() > 0 {
                debug!(generation, "auto stop skipped, players are online");
            } else {
                info!("no players online, stopping the server");
                runner.stop().await;
            }
        });
    }

    /// Bookkeeping after the server process is gone: invalidate pending auto
    /// stops, reset state, clear players, broadcast.
    fn on_server_exit(&self) {
        self.auto_stop_generation.fetch_add(1, Ordering::SeqCst);
        {
            let mut shared = self.lock_shared();
            shared.is_running = false;
            shared.auto_stop_time = NO_AUTO_STOP;
        }
        self.players.clear();
        self.stopping.store(false, Ordering::SeqCst);
        info!(server = %self.server.server_name, "server stopped");
        self.broadcast_state();
    }
}

/// Own the child for its whole lifetime: pump output, forward console input,
/// and perform the graceful stop with escalation.
async fn supervise(
    runner: Arc<Runner>,
    mut child: Child,
    stop: StopSettings,
    mut control_rx: mpsc::Receiver<Control>,
    mut console_rx: mpsc::Receiver<String>,
) {
    let mut stdin = child.stdin.take();
    let stdout_reader = tokio::spawn(pump_output(Arc::clone(&runner), child.stdout.take()));
    let stderr_reader = tokio::spawn(pump_output(Arc::clone(&runner), child.stderr.take()));

    let mut control_closed = false;
    let mut console_closed = false;
    let outcome = loop {
        tokio::select! {
            status = child.wait() => break Supervision::Exited(status),
            request = control_rx.recv(), if !control_closed => match request {
                Some(Control::GracefulStop) => break Supervision::StopRequested,
                // All senders are gone; the server cannot be stopped via
                // this channel anymore, so keep waiting for the exit.
                None => control_closed = true,
            },
            line = console_rx.recv(), if !console_closed => match line {
                Some(line) => forward_console_line(stdin.as_mut(), &line).await,
                None => console_closed = true,
            },
        }
    };

    let status = match outcome {
        Supervision::Exited(status) => status,
        Supervision::StopRequested => {
            perform_graceful_stop(&child, stdin.as_mut(), &stop).await;
            let raced = tokio::select! {
                status = child.wait() => Ok(status),
                () = sleep(stop.grace_period) => Err(()),
            };
            if let Ok(status) = raced {
                status
            } else {
                warn!(
                    grace_secs = stop.grace_period.as_secs(),
                    "grace period elapsed, killing the server"
                );
                if let Err(source) = child.start_kill() {
                    error!("could not kill the server process: {source}");
                }
                child.wait().await
            }
        }
    };

    // Drain remaining output so the tail of the log reaches the buffer and
    // the chat feed before the final state flip.
    let drain = async {
        if let Err(source) = stdout_reader.await {
            warn!("stdout reader task failed: {source}");
        }
        if let Err(source) = stderr_reader.await {
            warn!("stderr reader task failed: {source}");
        }
    };
    if tokio::time::timeout(READER_DRAIN_TIMEOUT, drain)
        .await
        .is_err()
    {
        warn!("server output readers did not finish in time; some final lines may be missing");
    }

    match &status {
        Ok(status) if status.success() => {
            info!("server terminated with no errors");
            telegram::send_message(
                &runner.global.telegram,
                &format!("Server {} stopped.", runner.server.server_name),
            );
            // The state flip in on_server_exit below waits for the backup,
            // mc-runner parity.
            restic::run_backup(&runner.global).await;
        }
        Ok(status) => {
            error!("server terminated with an error: {status}");
            telegram::send_message(
                &runner.global.telegram,
                &format!(
                    "Server {} terminated with error: {status}",
                    runner.server.server_name
                ),
            );
        }
        Err(source) => error!("could not wait on the server process: {source}"),
    }
    runner.on_server_exit();
}

/// Perform the configured graceful action: signal the process or write the
/// payload line to its stdin. Failures are logged, not fatal: the escalation
/// race still bounds how long a dead process can delay the stop.
async fn perform_graceful_stop(child: &Child, stdin: Option<&mut ChildStdin>, stop: &StopSettings) {
    match &stop.payload {
        StopPayload::Signal(signal) => {
            if let Some(pid) = child.id() {
                match i32::try_from(pid) {
                    Ok(pid) => match signals::send(pid, *signal) {
                        Ok(()) => debug!(pid, signal = ?signal, "sent graceful stop signal"),
                        Err(source) => {
                            warn!(pid, "could not send the graceful stop signal: {source}");
                        }
                    },
                    Err(source) => warn!("server pid {pid} is out of range: {source}"),
                }
            } else {
                debug!("server process already exited before the stop signal");
            }
        }
        StopPayload::Stdin(line) => {
            if let Some(pipe) = stdin {
                let result = pipe.write_all(line.as_bytes()).await;
                match result {
                    Ok(()) => debug!("sent the stop payload over stdin"),
                    Err(source) => {
                        warn!("could not write the stop payload to the server stdin: {source}");
                    }
                }
            } else {
                warn!("cannot stop by stdin: the server has no stdin pipe");
            }
        }
    }
}

async fn forward_console_line(stdin: Option<&mut ChildStdin>, line: &str) {
    let Some(pipe) = stdin else {
        return; // No pipe to write to: drop the line.
    };
    let mut buffered = line.to_string();
    buffered.push('\n');
    if let Err(source) = pipe.write_all(buffered.as_bytes()).await {
        debug!("could not forward console input to the server: {source}");
    }
}

/// Read one output pipe line by line into the runner (log buffer, chat feed,
/// player tracking). Ends when the child closes the pipe.
async fn pump_output(runner: Arc<Runner>, pipe: Option<impl AsyncRead + Unpin>) {
    let Some(pipe) = pipe else {
        warn!("server output pipe was not captured; that output is lost");
        return;
    };
    let mut lines = BufReader::new(pipe).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => runner.on_output_line(&line),
            Ok(None) => break,
            Err(source) => {
                warn!("could not read server output: {source}");
                break;
            }
        }
    }
}
