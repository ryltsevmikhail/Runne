//! Fresh desktop admission for the fixed qualification bootstrap transport.

#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code)
)]

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::path::{Path, PathBuf};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use super::{
    NativeEnrollmentArtifactPathsV1, NativeEnrollmentQualification, NativeEnrollmentTupleAdmission,
    enrollment_daemon_installed::{
        compiled_policy, refresh_retained_admission_at, verified_admission,
    },
};

/// Opaque current-desktop admission for the fixed qualification bootstrap transport.
///
/// It grants no ordinary runtime, credential, qualification, or profile capability.
///
/// ```compile_fail
/// use runne_platform_desktop::VerifiedInstalledQualificationBootstrapDesktop;
/// let _ = VerifiedInstalledQualificationBootstrapDesktop {};
/// ```
///
/// ```compile_fail
/// use runne_platform_desktop::VerifiedInstalledQualificationBootstrapDesktop;
/// fn clone_required<T: Clone>() {}
/// clone_required::<VerifiedInstalledQualificationBootstrapDesktop>();
/// ```
///
/// ```compile_fail
/// use runne_platform_desktop::VerifiedInstalledQualificationBootstrapDesktop;
/// fn wire_required<T: serde::Serialize>() {}
/// wire_required::<VerifiedInstalledQualificationBootstrapDesktop>();
/// ```
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub struct VerifiedInstalledQualificationBootstrapDesktop {
    paths: NativeEnrollmentArtifactPathsV1,
    admission: NativeEnrollmentTupleAdmission,
    profile_directory: PathBuf,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[path = "bootstrap_desktop/offer.rs"]
mod offer;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[path = "bootstrap_desktop/run_root.rs"]
mod run_root;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use offer::{PreparedDesktopQualificationRun, VerifiedDesktopQualificationOffer};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl VerifiedInstalledQualificationBootstrapDesktop {
    /// Admits only the current signed desktop package and its committed journals.
    #[must_use]
    pub fn admit_current_for_desktop(profile_directory: &Path) -> Option<Self> {
        let paths = NativeEnrollmentArtifactPathsV1::resolve_installed().ok()?;
        let policy = compiled_policy()?;
        let trust = crate::CompiledUpdateTrustRootV2::load()?.into_trust_root();
        let admission = verified_admission(profile_directory, &paths, &trust, &policy)?;
        if !current_desktop_admission(&paths, &admission) {
            return None;
        }
        let admission = refresh_retained_admission_at(
            profile_directory,
            &paths,
            &trust,
            &policy,
            &admission,
            now()?,
        )?;
        current_desktop_admission(&paths, &admission).then_some(Self {
            paths,
            admission,
            profile_directory: profile_directory.to_path_buf(),
        })
    }

    /// Revalidates the retained journals, installed package, code identity, and pins.
    #[must_use]
    pub fn revalidate(self) -> Option<Self> {
        let policy = compiled_policy()?;
        let trust = crate::CompiledUpdateTrustRootV2::load()?.into_trust_root();
        let admission = refresh_retained_admission_at(
            &self.profile_directory,
            &self.paths,
            &trust,
            &policy,
            &self.admission,
            now()?,
        )?;
        current_desktop_admission(&self.paths, &admission).then_some(Self { admission, ..self })
    }

    /// Builds only the fixed desktop bootstrap transport after a fresh admission.
    #[must_use]
    pub fn prepare_bootstrap_transport(
        self,
    ) -> Option<(
        Self,
        runne_macos_xpc::QualificationRunnerEndpointConfiguration,
    )> {
        let fresh = self.revalidate()?;
        let configuration = fresh
            .admission
            .bootstrap_client_pins
            .as_ref()?
            .desktop_bootstrap_configuration()
            .ok()?;
        Some((fresh, configuration))
    }

    /// Confirms a root-prepared binding against a fresh current-desktop admission.
    #[must_use]
    pub fn confirm_bootstrap_binding(self, binding: &runne_api::RunBinding) -> Option<Self> {
        let fresh = self.revalidate()?;
        fresh
            .admission
            .bootstrap_client_pins
            .as_ref()?
            .matches_prepared_binding(binding)
            .then_some(fresh)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn current_desktop_admission(
    paths: &NativeEnrollmentArtifactPathsV1,
    admission: &NativeEnrollmentTupleAdmission,
) -> bool {
    matches!(
        admission.qualification(),
        NativeEnrollmentQualification::Unqualified
    ) && admission.bootstrap_client_pins.is_some()
        && admission
            .macos_desktop_code_identity
            .as_ref()
            .is_some_and(|identity| {
                paths
                    .confirm_current_macos_desktop(admission.desktop_sha256, identity)
                    .is_ok()
            })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn now() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod tests {
    use super::VerifiedInstalledQualificationBootstrapDesktop;

    #[test]
    fn current_test_binary_outside_fixed_runne_package_is_rejected() {
        assert!(
            VerifiedInstalledQualificationBootstrapDesktop::admit_current_for_desktop(
                std::path::Path::new("/")
            )
            .is_none()
        );
    }
}
