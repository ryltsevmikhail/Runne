#[cfg(feature = "desktop-protected")]
use super::launch::ProtectedDaemonLaunch;
use super::*;
#[cfg(feature = "desktop-protected")]
use crate::application::workspace_internal::{self, ProtectedProviderDependencyCapsule};
use crate::error::DaemonError;
#[cfg(feature = "desktop-protected")]
use std::future::Future;
#[cfg(feature = "desktop-protected")]
use std::path::Path;

/// Runs one entire authenticated protected launch without exposing control material.
pub fn run_verified_protected_channel(
    channel: ProtectedActivationChannel,
) -> Result<(), DaemonError> {
    #[cfg(feature = "desktop-protected")]
    {
        run_verified_protected_channel_with_fixture(channel, |_| async {
            Ok((ProtectedProviderDependencyCapsule::production(), ()))
        })
    }
    #[cfg(not(feature = "desktop-protected"))]
    {
        let _ = channel;
        Err(protected_activation_error())
    }
}

#[cfg(feature = "desktop-protected")]
pub(crate) fn run_verified_protected_channel_with_fixture<F, Fut, Keepalive>(
    channel: ProtectedActivationChannel,
    fixture: F,
) -> Result<(), DaemonError>
where
    F: FnOnce(&Path) -> Fut,
    Fut: Future<Output = Result<(ProtectedProviderDependencyCapsule, Keepalive), DaemonError>>,
{
    run_desktop_protected_channel(channel, fixture)
}

#[cfg(feature = "desktop-protected")]
fn run_desktop_protected_channel<F, Fut, Keepalive>(
    mut channel: ProtectedActivationChannel,
    fixture: F,
) -> Result<(), DaemonError>
where
    F: FnOnce(&Path) -> Fut,
    Fut: Future<Output = Result<(ProtectedProviderDependencyCapsule, Keepalive), DaemonError>>,
{
    let executable = std::env::current_exe().map_err(|_| protected_activation_error())?;
    let mut launch = ProtectedDaemonLaunch::accept(&mut channel, &executable, launch_time)
        .map_err(|_| protected_activation_error())?;
    tokio::runtime::Runtime::new()
        .map_err(|_| protected_activation_error())?
        .block_on(async move {
            let runtime_root = std::path::Path::new(&launch.config().db_path)
                .parent()
                .and_then(Path::parent)
                .map(Path::to_path_buf)
                .ok_or_else(protected_activation_error)?;
            let runtime_root = runtime_root.as_path();
            let (dependencies, _fixture_keepalive) = fixture(runtime_root)
                .await
                .map_err(|_| protected_activation_error())?;
            let start = launch
                .bootstrap_runtime_start(launch_time)
                .map_err(|_| protected_activation_error())?;
            let control_keys = launch.keys().clone();
            let application =
                workspace_internal::start_from_verified_protected_launch(start, dependencies)
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
                #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                let enrollment_transition =
                    enrollment_transition_composition(&application, request, runtime_root)?;
                tokio::task::spawn_blocking(move || {
                    run_control_loop_v2(
                        channel,
                        control_keys,
                        owned,
                        sessions,
                        clock,
                        #[cfg(feature = "desktop-protected")]
                        roots,
                        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                        enrollment_transition,
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

/// Composes the same-process enrollment transition from daemon-owned facts.
///
/// `None` means this installation carries no admitted enrollment anchor; a
/// prepare frame then fails closed as an unknown control frame.
#[cfg(all(
    feature = "desktop-protected",
    target_os = "macos",
    target_arch = "aarch64"
))]
fn enrollment_transition_composition(
    application: &crate::application::DaemonApplication,
    request: &runne_api::ProtectedLaunchRequestV2,
    runtime_root: &Path,
) -> Result<
    Option<(
        super::enrollment_control_transition::EnrollmentControlComposition,
        super::installation_anchor::VerifiedNativeEnrollmentInstallation,
    )>,
    DaemonError,
> {
    use super::enrollment_control_transition::EnrollmentControlComposition;

    let Ok(facts) = application.protected_enrollment_facts() else {
        return Ok(None);
    };
    let Some(profile_directory) = runtime_root.parent() else {
        return Ok(None);
    };
    let composition = EnrollmentControlComposition::new(
        request.clone(),
        *facts.installation.installation_identity_digest(),
        facts.provider_readiness,
        facts.endpoint,
        facts.certificate_sha256,
        facts.certificate_der,
        facts.capabilities,
        profile_directory.to_path_buf(),
        super::control_v3::macos_continuous_ticket_clock(),
    );
    Ok(Some((composition, facts.installation)))
}

#[cfg(feature = "desktop-protected")]
fn launch_time() -> Result<u64, LaunchAuthorityError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .ok_or(LaunchAuthorityError::StaleLaunchAuthority)
}
