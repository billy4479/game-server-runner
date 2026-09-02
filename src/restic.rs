//! Restic backups after a clean server exit, carried over from mc-runner.

use tracing::{error, info};

use crate::config::Config;

/// Run `restic backup` over the server directory and wait for it to finish.
///
/// A no-op unless `restic_enable` is set. The command inherits the runner's
/// environment, so restic reads `RESTIC_PASSWORD`, `RESTIC_REPOSITORY` and
/// friends from it. Failures are logged with the captured output and never
/// propagated: a broken backup must not take the runner down.
pub async fn run_backup(global: &Config) {
    if !global.restic_enable {
        return;
    }
    info!("starting restic backup");
    let outcome = tokio::process::Command::new(&global.restic_path)
        .args(["backup", &global.server_dir, "--repo", &global.restic_repo])
        .output()
        .await;
    match outcome {
        Ok(output) if output.status.success() => {
            info!("restic backup finished");
        }
        Ok(output) => {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            error!(
                status = %output.status,
                output = %combined,
                "restic backup failed"
            );
        }
        Err(source) => error!("could not run restic: {source}"),
    }
}
