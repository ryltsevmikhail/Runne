//! GOCODE Runtime Daemon.

#[cfg(unix)]
use gocode_api::LaunchAuthorityError;
use gocode_daemon::application::DaemonApplication;
use gocode_daemon::config::load_external_config;
#[cfg(unix)]
use gocode_daemon::error::DaemonError;
#[cfg(unix)]
use gocode_daemon::protected_activation::{
    ProtectedActivationChannel, ProtectedDaemonLaunch, run_control_loop, run_control_loop_v2,
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
    let config = load_external_config().map_err(|error| {
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

#[cfg(unix)]
fn run_protected(mut channel: ProtectedActivationChannel) -> Result<(), ()> {
    let executable_path = std::env::current_exe().map_err(|_| ())?;
    let mut launch = ProtectedDaemonLaunch::accept(&mut channel, &executable_path, || {
        unix_time_millis().ok_or(LaunchAuthorityError::StaleLaunchAuthority)
    })
    .map_err(|_| ())?;
    if launch.provider_activation().requires_openai_execution() {
        // The protected V2 transcript is preserved, but no readiness may be
        // emitted until the exact credential-backed composition is available.
        return Err(());
    }
    let bootstrap = launch
        .bootstrap(|| unix_time_millis().ok_or(LaunchAuthorityError::StaleLaunchAuthority))
        .map_err(|_| ())?;
    let runtime = tokio::runtime::Runtime::new().map_err(|_| ())?;
    runtime
        .block_on(async move {
            let application = DaemonApplication::start_protected(
                launch.config(),
                bootstrap,
                launch.provider_activation().clone(),
            )
            .await
            .map_err(|_| ())?;
            let keys = launch.keys().clone();
            let local_session_service = application.protected_session_service().map_err(|_| ())?;
            let session_clock = application.protected_session_clock().map_err(|_| ())?;
            let control_loop = if let Some(request) = launch.request_v1() {
                let ready = application
                    .protected_ready(request, launch.keys())
                    .map_err(|_| ())?;
                let owned_launch = ready.owned_launch();
                channel
                    .write_control_frame(&ready.encode_frame().map_err(|_| ())?)
                    .map_err(|_| ())?;
                tokio::task::spawn_blocking(move || {
                    run_control_loop(
                        channel,
                        keys,
                        owned_launch,
                        local_session_service,
                        session_clock,
                    )
                })
            } else if let Some(request) = launch.request_v2() {
                let ready = application
                    .protected_ready_v2(request, launch.keys())
                    .map_err(|_| ())?;
                let owned_launch = ready.owned_launch();
                channel
                    .write_control_frame(&ready.encode_frame().map_err(|_| ())?)
                    .map_err(|_| ())?;
                tokio::task::spawn_blocking(move || {
                    run_control_loop_v2(
                        channel,
                        keys,
                        owned_launch,
                        local_session_service,
                        session_clock,
                    )
                })
            } else {
                return Err(());
            };
            application
                .run(async move {
                    control_loop
                        .await
                        .map_err(|_| {
                            DaemonError::Bootstrap("protected control task failed".into())
                        })?
                        .map_err(|_| {
                            DaemonError::Bootstrap("protected control channel closed".into())
                        })
                })
                .await
                .map_err(|_| ())
        })
        .map_err(|_| ())
}

#[cfg(unix)]
fn unix_time_millis() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
}
