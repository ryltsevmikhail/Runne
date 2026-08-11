use super::*;
#[cfg(feature = "desktop-protected")]
use crate::application::workspace_internal::{self, ProtectedProviderDependencyCapsule};
use crate::error::DaemonError;

/// Runs one entire authenticated protected launch without exposing control material.
pub fn run_verified_protected_channel(
    channel: ProtectedActivationChannel,
) -> Result<(), DaemonError> {
    #[cfg(not(feature = "desktop-protected"))]
    {
        let _ = channel;
        return Err(protected_activation_error());
    }
    #[cfg(feature = "desktop-protected")]
    run_desktop_protected_channel(channel)
}

#[cfg(feature = "desktop-protected")]
fn run_desktop_protected_channel(
    mut channel: ProtectedActivationChannel,
) -> Result<(), DaemonError> {
    let executable = std::env::current_exe().map_err(|_| protected_activation_error())?;
    let mut launch = ProtectedDaemonLaunch::accept(&mut channel, &executable, launch_time)
        .map_err(|_| protected_activation_error())?;
    tokio::runtime::Runtime::new()
        .map_err(|_| protected_activation_error())?
        .block_on(async move {
            let start = launch
                .bootstrap_runtime_start(launch_time)
                .map_err(|_| protected_activation_error())?;
            let control_keys = launch.keys().clone();
            let application = workspace_internal::start_from_verified_protected_launch(
                start,
                ProtectedProviderDependencyCapsule::production(),
            )
            .await
            .map_err(|_| protected_activation_error())?;
            let sessions = application
                .protected_session_service()
                .map_err(|_| protected_activation_error())?;
            let clock = application
                .protected_session_clock()
                .map_err(|_| protected_activation_error())?;
            #[cfg(feature = "desktop-protected")]
            let roots = Some(
                application
                    .protected_root_control()
                    .map_err(|_| protected_activation_error())?,
            );
            let control = if let Some(request) = launch.request_v1() {
                let ready = application
                    .protected_ready(request, launch.keys())
                    .map_err(|_| protected_activation_error())?;
                channel
                    .write_control_frame(
                        &ready
                            .encode_frame()
                            .map_err(|_| protected_activation_error())?,
                    )
                    .map_err(|_| protected_activation_error())?;
                let owned = ready.owned_launch();
                tokio::task::spawn_blocking(move || {
                    run_control_loop(
                        channel,
                        control_keys,
                        owned,
                        sessions,
                        clock,
                        #[cfg(feature = "desktop-protected")]
                        roots,
                    )
                })
            } else if let Some(request) = launch.request_v2() {
                let ready = application
                    .protected_ready_v2(request, launch.keys())
                    .map_err(|_| protected_activation_error())?;
                channel
                    .write_control_frame(
                        &ready
                            .encode_frame()
                            .map_err(|_| protected_activation_error())?,
                    )
                    .map_err(|_| protected_activation_error())?;
                let owned = ready.owned_launch();
                tokio::task::spawn_blocking(move || {
                    run_control_loop_v2(
                        channel,
                        control_keys,
                        owned,
                        sessions,
                        clock,
                        #[cfg(feature = "desktop-protected")]
                        roots,
                    )
                })
            } else {
                return Err(protected_activation_error());
            };
            application
                .run(async move {
                    control
                        .await
                        .map_err(|_| {
                            DaemonError::Bootstrap("protected control task failed".into())
                        })?
                        .map_err(|_| {
                            DaemonError::Bootstrap("protected control channel closed".into())
                        })
                })
                .await
                .map_err(|_| protected_activation_error())
        })
}

fn protected_activation_error() -> DaemonError {
    DaemonError::Bootstrap("protected activation failed".into())
}

#[cfg(feature = "desktop-protected")]
fn launch_time() -> Result<u64, LaunchAuthorityError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .ok_or(LaunchAuthorityError::StaleLaunchAuthority)
}
