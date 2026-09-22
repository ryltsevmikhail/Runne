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
        #[cfg(all(unix, feature = "test-support", not(test)))]
        if runne_api::test_support::local_credential_service_fixture_enabled() {
            return run_verified_protected_channel_with_fixture(channel, |runtime_root| {
                let runtime_root = runtime_root.to_path_buf();
                async move { super::loopback_fixture::service_dependencies(&runtime_root).await }
            });
        }
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
            launch
                .revalidate_enrollment_capability(&channel)
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
                #[cfg(all(unix, feature = "desktop-protected"))]
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
                        #[cfg(all(unix, feature = "desktop-protected"))]
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
#[cfg(all(feature = "desktop-protected", unix))]
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
    let Some(profile_directory) = enrollment_profile_directory(runtime_root) else {
        return Ok(None);
    };
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let enrollment_control =
        Some(facts.credential_enrollment_control.clone().ok_or_else(|| {
            DaemonError::Bootstrap("credential enrollment control unavailable".into())
        })?);
    // Off macOS there is no credential enrollment control yet; the V3 loop
    // enters without the credential-service phase (fail-closed broker only).
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    let enrollment_control = facts.credential_enrollment_control.clone();
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let ticket_clock = super::control_v3::macos_continuous_ticket_clock();
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    let ticket_clock = super::control_v3::unix_wall_ticket_clock();
    let composition = EnrollmentControlComposition::new(
        request.clone(),
        *facts.installation.installation_identity_digest(),
        facts.provider_readiness,
        facts.endpoint,
        facts.certificate_sha256,
        facts.certificate_der,
        facts.capabilities,
        profile_directory.to_path_buf(),
        runtime_root.to_path_buf(),
        ticket_clock,
        enrollment_control,
    );
    Ok(Some((composition, facts.installation)))
}

#[cfg(all(feature = "desktop-protected", unix))]
#[cfg_attr(
    all(not(test), target_os = "macos", target_arch = "aarch64"),
    allow(unused_variables, unreachable_code)
)]
fn enrollment_profile_directory(runtime_root: &Path) -> Option<std::path::PathBuf> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        runtime_root.parent().map(Path::to_path_buf)
    }
    #[cfg(all(target_os = "linux", feature = "desktop-protected"))]
    {
        profile_directory::enrollment_profile_directory(runtime_root)
    }
    #[cfg(not(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "linux", feature = "desktop-protected")
    )))]
    {
        let _ = runtime_root;
        // Off macOS/Linux the profile directory is not derived from the runtime
        // root yet; the updater-journal layout lands with D1.2 packaging.
        None
    }
}

#[cfg(all(test, feature = "desktop-protected", target_os = "linux"))]
mod linux_profile_directory_tests {
    use super::enrollment_profile_directory;

    fn layout(temporary: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;
        let profile_directory = temporary.join("com.runne.desktop");
        let runtime_root = profile_directory.join("bundled-runtime");
        std::fs::create_dir_all(&runtime_root).expect("layout created");
        std::fs::set_permissions(&profile_directory, std::fs::Permissions::from_mode(0o700))
            .expect("profile mode set");
        (profile_directory, runtime_root)
    }

    #[test]
    fn linux_derives_profile_directory_from_runtime_root_parent() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let (profile_directory, runtime_root) = layout(temporary.path());
        assert_eq!(
            enrollment_profile_directory(&runtime_root),
            Some(profile_directory)
        );
    }

    #[test]
    fn linux_rejects_runtime_root_without_bundled_runtime_leaf() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let runtime_root = temporary.path().join("com.runne.desktop").join("other");
        std::fs::create_dir_all(&runtime_root).expect("layout created");
        assert_eq!(enrollment_profile_directory(&runtime_root), None);
    }

    #[test]
    fn linux_rejects_missing_profile_directory() {
        let runtime_root = std::path::Path::new("/nonexistent-runne-enroll51")
            .join("com.runne.desktop")
            .join("bundled-runtime");
        assert_eq!(enrollment_profile_directory(&runtime_root), None);
    }

    #[test]
    fn linux_symlinked_profile_directory_is_rejected() {
        // A symlinked profile directory must fail closed even though the
        // resolved target is a valid directory: `.is_dir()` follows symlinks,
        // so the derivation uses symlink_metadata instead.
        let temporary = tempfile::tempdir().expect("tempdir");
        let real = temporary.path().join("real-profile");
        std::fs::create_dir_all(real.join("bundled-runtime")).expect("real layout created");
        std::fs::set_permissions(
            &real,
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("mode set");
        let link = temporary.path().join("com.runne.desktop");
        std::os::unix::fs::symlink(&real, &link).expect("symlink created");
        assert_eq!(
            enrollment_profile_directory(&link.join("bundled-runtime")),
            None
        );
    }

    #[test]
    fn linux_group_or_world_accessible_profile_directory_is_rejected() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let (profile_directory, runtime_root) = layout(temporary.path());
        std::fs::set_permissions(
            &profile_directory,
            std::fs::Permissions::from_mode(0o755),
        )
        .expect("loose mode set");
        assert_eq!(enrollment_profile_directory(&runtime_root), None);
    }

    #[test]
    fn linux_derivation_is_structural_and_ignores_journal_presence() {
        // Journal content validation is downstream (macOS admission today);
        // on Linux the composition stays a pure structural mapping and the
        // peer proof is the kernel credential plus the signed V2 claims.
        let temporary = tempfile::tempdir().expect("tempdir");
        let (profile_directory, runtime_root) = layout(temporary.path());
        assert!(!profile_directory.join("updates").exists());
        assert_eq!(
            enrollment_profile_directory(&runtime_root),
            Some(profile_directory)
        );
    }
}

#[cfg(all(
    test,
    feature = "desktop-protected",
    target_os = "macos",
    target_arch = "aarch64"
))]
#[test]
fn enrollment_composition_uses_runtime_root_parent_for_updater_journals() {
    let profile_directory = Path::new("/private/var/runne");
    let runtime_root = profile_directory.join("bundled-runtime");
    assert_eq!(
        enrollment_profile_directory(&runtime_root),
        Some(profile_directory.to_path_buf())
    );
}

#[cfg(feature = "desktop-protected")]
fn launch_time() -> Result<u64, LaunchAuthorityError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .ok_or(LaunchAuthorityError::StaleLaunchAuthority)
}

#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
mod profile_directory;
