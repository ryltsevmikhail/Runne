//! GOCODE Runtime Daemon.

use gocode_daemon::application::DaemonApplication;
use gocode_daemon::config::load_config;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let config = load_config(None).map_err(|error| {
        eprintln!("fatal: config error: {error}");
        std::process::exit(1);
    })?;

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let application = DaemonApplication::start(&config).await.map_err(|error| {
            eprintln!("fatal: bootstrap error: {error}");
            std::process::exit(2);
        })?;
        tracing::info!(
            authority_id = hex::encode(application.authority_id()),
            db_existed = application.db_existed(),
            bind = %application.local_addr()?,
            "bootstrap complete, canonical runtime ready"
        );
        tracing::info!("daemon ready, press Ctrl+C to stop");

        application
            .run(async { tokio::signal::ctrl_c().await.map_err(Into::into) })
            .await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;

    Ok(())
}
