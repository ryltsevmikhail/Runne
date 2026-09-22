//! Enrollment transition composition for the protected launch path.
//!
//! Split out of `host/mod.rs` (ENROLL-51-INTEGRATE rework): the V2 launch
//! composition plus the platform-specific `enrollment_profile_directory`
//! derivation dispatch and their tests. The channel/launch plumbing stays in
//! `host/mod.rs`.

use super::profile_directory;
use crate::error::DaemonError;
use std::path::Path;

/// Composes the same-process enrollment transition from daemon-owned facts.
///
/// `None` means this installation carries no admitted enrollment anchor; a
/// prepare frame then fails closed as an unknown control frame.
#[cfg(all(feature = "desktop-protected", unix))]
pub(super) fn enrollment_transition_composition(
    application: &crate::application::DaemonApplication,
    request: &runne_api::ProtectedLaunchRequestV2,
    runtime_root: &Path,
) -> Result<
    Option<(
        super::super::enrollment_control_transition::EnrollmentControlComposition,
        super::super::installation_anchor::VerifiedNativeEnrollmentInstallation,
    )>,
    DaemonError,
> {
    use super::super::enrollment_control_transition::EnrollmentControlComposition;

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
    let ticket_clock = super::super::control_v3::macos_continuous_ticket_clock();
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    let ticket_clock = super::super::control_v3::unix_wall_ticket_clock();
    let composition = EnrollmentControlComposition::new(
        request.clone(),
        *facts.installation.installation_identity_digest(),
        facts.provider_readiness,
        facts.endpoint,
        facts.certificate_sha256,
        facts.certificate_der,
        facts.capabilities,
        profile_directory,
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
    use std::os::unix::fs::PermissionsExt as _;

    fn layout(temporary: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
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
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).expect("mode set");
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
        std::fs::set_permissions(&profile_directory, std::fs::Permissions::from_mode(0o755))
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
