//! GOCODE Runtime Daemon.

use gocode_daemon::application::DaemonApplication;
#[cfg(unix)]
use gocode_daemon::protected_activation::{
    ProtectedActivationChannel, run_verified_protected_channel,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    #[cfg(unix)]
    match ProtectedActivationChannel::from_inherited_stdin() {
        Ok(Some(channel)) => {
            if run_protected(channel).is_err() {
                eprintln!("fatal: protected activation failed");
                std::process::exit(2);
            }
            return Ok(());
        }
        Ok(None) => {}
        Err(_) => {
            eprintln!("fatal: protected activation channel failed");
            std::process::exit(2);
        }
    }

    run_external()
}

fn run_external() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let application = DaemonApplication::start_external_from_fixed_source()
            .await
            .map_err(|error| {
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

#[cfg(unix)]
fn run_protected(
    channel: ProtectedActivationChannel,
) -> Result<(), gocode_daemon::error::DaemonError> {
    run_verified_protected_channel(channel)
}
