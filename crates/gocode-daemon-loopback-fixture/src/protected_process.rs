use std::path::{Path, PathBuf};
use std::sync::Arc;

use gocode_api::LaunchAuthorityError;
use gocode_daemon::application::workspace_internal::{self, ProtectedProviderDependencyCapsule};
use gocode_daemon::error::DaemonError;
use gocode_daemon::protected_activation::{
    ProtectedActivationChannel, ProtectedDaemonLaunch, run_control_loop_v2,
};

use crate::{
    RetainedFixtureKeyring, TlsSseServer, ack_failure_decorator, loopback_effect,
    loopback_request_authenticator,
};

/// Runs one argument-free fixture daemon over the inherited protected channel.
#[allow(clippy::result_unit_err)]
pub fn run_protected_fixture() -> Result<(), ()> {
    if std::env::args_os().count() != 1 {
        return Err(());
    }
    let channel = ProtectedActivationChannel::from_inherited_stdin().map_err(|_| ())?;
    let channel = channel.ok_or(())?;
    run_protected(channel)
}

fn run_protected(mut channel: ProtectedActivationChannel) -> Result<(), ()> {
    let executable = std::env::current_exe().map_err(|_| ())?;
    let mut launch =
        ProtectedDaemonLaunch::accept(&mut channel, &executable, now).map_err(|_| ())?;
    if launch.request_v2().is_none() {
        return Err(());
    }
    let runtime_root = runtime_root_from_database_path(&launch.config().db_path)?;
    let runtime = tokio::runtime::Runtime::new().map_err(|_| ())?;
    runtime.block_on(async move {
        let server = TlsSseServer::start(&runtime_root, loopback_request_authenticator()).await?;
        let keyring = Arc::new(RetainedFixtureKeyring::open(&runtime_root).map_err(|_| ())?);
        let (effect, _) = loopback_effect(server.client()?)?;
        let start = launch.bootstrap_application_start(now).map_err(|_| ())?;
        let keys = launch.keys().clone();
        let request = launch.request_v2().ok_or(())?;
        let application = workspace_internal::start_from_verified_protected_launch(
            start,
            ProtectedProviderDependencyCapsule::from_loopback_fixture(
                effect,
                keyring,
                ack_failure_decorator(),
                crate::credential_versions::factory(),
            ),
        )
        .await
        .map_err(|_| ())?;
        let ready = application
            .protected_ready_v2(request, launch.keys())
            .map_err(|_| ())?;
        let owned_launch = ready.owned_launch();
        channel
            .write_control_frame(&ready.encode_frame().map_err(|_| ())?)
            .map_err(|_| ())?;
        let local_session_service = application.protected_session_service().map_err(|_| ())?;
        let session_clock = application.protected_session_clock().map_err(|_| ())?;
        let control_loop = tokio::task::spawn_blocking(move || {
            run_control_loop_v2(
                channel,
                keys,
                owned_launch,
                local_session_service,
                session_clock,
            )
        });
        application
            .run(async move {
                control_loop
                    .await
                    .map_err(|_| DaemonError::Bootstrap("fixture control task failed".into()))?
                    .map_err(|_| DaemonError::Bootstrap("fixture control channel closed".into()))
            })
            .await
            .map_err(|_| ())?;
        drop(server);
        Ok(())
    })
}

fn runtime_root_from_database_path(path: &str) -> Result<PathBuf, ()> {
    Path::new(path)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or(())
}

fn now() -> Result<u64, LaunchAuthorityError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or(LaunchAuthorityError::StaleLaunchAuthority)
}
