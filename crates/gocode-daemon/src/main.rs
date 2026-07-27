//! GOCODE Runtime Daemon
//!
//! Executable daemon binary implementing Phase 4:
//! configuration, token, lock, bootstrap, shutdown, and HTTP host.

use gocode_daemon::bootstrap::bootstrap;
use gocode_daemon::config::load_config;
use gocode_daemon::shutdown::{RuntimeTaskSupervisor, graceful_shutdown};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let config = load_config(None).map_err(|e| {
        eprintln!("fatal: config error: {e}");
        std::process::exit(1);
    })?;

    let outcome = bootstrap(&config).map_err(|e| {
        eprintln!("fatal: bootstrap error: {e}");
        std::process::exit(2);
    })?;

    let supervisor = RuntimeTaskSupervisor::new();

    tracing::info!(
        authority_id = hex::encode(outcome.authority_id),
        db_existed = outcome.db_existed,
        "bootstrap complete, daemon running"
    );

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        // Wait for signal
        let _handle = supervisor.register();
        tracing::info!("daemon ready, press Ctrl+C to stop");
        tokio::signal::ctrl_c().await?;
        graceful_shutdown(&supervisor, config.shutdown_timeout_ms).await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;

    Ok(())
}
