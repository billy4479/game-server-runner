//! Entry point: load config, init logging, serve the web API, and shut down
//! gracefully on ctrl-c/SIGTERM, stopping the game server on the way out.

mod clock;
mod config;
mod db;
mod players;
mod restic;
mod server;
mod signals;
mod state;
mod telegram;
mod tokens;
mod web;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tracing::{debug, error, info};

use crate::config::ConfigError;
use crate::server::Runner;

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            report_startup_error(&AppError::Io(err));
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(run());
    // The console forwarder parks a blocking-pool thread in a read on our
    // stdin. That read cannot be interrupted, and it would make a plain
    // runtime drop wait forever, so give it a bounded shutdown instead.
    runtime.shutdown_timeout(Duration::from_millis(500));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            report_startup_error(&err);
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("config: {0}")]
    Config(#[from] ConfigError),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("database: {0}")]
    Db(#[from] db::DbError),
}

/// Logging may not be configured yet when startup fails, so this goes
/// straight to stderr.
fn report_startup_error(err: &AppError) {
    #[expect(
        clippy::print_stderr,
        reason = "startup errors can happen before tracing is configured"
    )]
    fn print_to_stderr(err: &AppError) {
        eprintln!("error: {err}");
    }
    print_to_stderr(err);
}

async fn run() -> Result<(), AppError> {
    let config_path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| String::from("config.toml"));
    let global = Arc::new(config::load_global_config(&PathBuf::from(config_path))?);

    init_tracing(&global.log_level);
    debug!(
        db_path = %global.db_path,
        restic_enable = global.restic_enable,
        restic_repo = %global.restic_repo,
        restic_path = %global.restic_path,
        telegram_configured = global.telegram.token_configured(),
        telegram_chats = global.telegram.chat_id_count(),
        "configuration loaded"
    );
    info!(version = env!("CARGO_PKG_VERSION"), "game-server-runner");

    let server = config::load_server_config(Path::new(&global.server_dir))?;
    let runner = Arc::new(Runner::new(Arc::clone(&global), server));
    Runner::spawn_console_forwarder(&runner);

    let db = db::init(&global.db_path).await?;
    db::ensure_admin_token(&db).await?;
    db::spawn_cleanup_task(db.clone());

    let port = global.port;
    let listener = TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port)).await?;
    info!(port, "setup completed, starting the application");

    let app = web::router(web::AppState {
        runner: Arc::clone(&runner),
        db,
    });
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(runner))
        .await?;
    Ok(())
}

fn init_tracing(level: &str) {
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(config::log_level_filter(level).into())
        .parse_lossy("");
    // stderr, so stdout stays reserved for data and the admin invitation
    // token is greppable from the journal/stderr like in mc-runner.
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

/// Resolves once ctrl-c or SIGTERM arrives; then the game server is stopped
/// gracefully and we wait for it to be gone before returning.
async fn shutdown_signal(runner: Arc<Runner>) {
    let ctrl_c = async {
        if let Err(source) = tokio::signal::ctrl_c().await {
            error!("could not listen for ctrl-c: {source}");
            std::future::pending::<()>().await;
        }
    };
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(source) => {
                error!("could not listen for SIGTERM: {source}");
                std::future::pending::<()>().await;
            }
        }
    };
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    info!("shutdown signal received, stopping the game server");
    runner.notify_shutdown();
    runner.stop().await;
    runner.join_supervisor().await;
    info!("shutdown complete");
}
