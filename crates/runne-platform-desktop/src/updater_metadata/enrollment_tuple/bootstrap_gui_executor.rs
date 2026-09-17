use std::path::{Path, PathBuf};

#[path = "bootstrap_gui_executor/launch.rs"]
mod launch;
#[path = "bootstrap_gui_executor/root_artifact.rs"]
pub(super) mod root_artifact;
use root_artifact::RootBootstrapArtifact;

use super::{
    NativeEnrollmentArtifactPathsV1, NativeEnrollmentQualification, NativeEnrollmentTupleAdmission,
    enrollment_daemon_installed::{
        compiled_policy, refresh_retained_admission_at, verified_admission,
    },
    enrollment_measurement::OpenedNativeEnrollmentFile,
};

/// Opaque admission for the current fixed GUI qualification executor only.
///
/// ```compile_fail
/// use runne_platform_desktop::VerifiedInstalledQualificationGuiExecutor;
/// let _ = VerifiedInstalledQualificationGuiExecutor {};
/// ```
///
/// ```compile_fail
/// use runne_platform_desktop::VerifiedInstalledQualificationGuiExecutor;
/// fn clone_required<T: Clone>() {}
/// clone_required::<VerifiedInstalledQualificationGuiExecutor>();
/// ```
///
/// ```compile_fail
/// use runne_platform_desktop::VerifiedInstalledQualificationGuiExecutor;
/// fn wire_required<T: serde::Serialize>() {}
/// wire_required::<VerifiedInstalledQualificationGuiExecutor>();
/// ```
pub struct VerifiedInstalledQualificationGuiExecutor {
    paths: NativeEnrollmentArtifactPathsV1,
    executor: OpenedNativeEnrollmentFile,
    root_artifact: RootBootstrapArtifact,
    admission: NativeEnrollmentTupleAdmission,
    profile_directory: PathBuf,
}

impl VerifiedInstalledQualificationGuiExecutor {
    /// Admits only the current, fixed-name signed GUI executor package member.
    #[must_use]
    pub fn admit_current_for_gui_executor(profile_directory: &Path) -> Option<Self> {
        let (paths, executor) =
            NativeEnrollmentArtifactPathsV1::resolve_current_gui_executor().ok()?;
        let policy = compiled_policy()?;
        let trust = crate::CompiledUpdateTrustRootV2::load()?.into_trust_root();
        let admission = verified_admission(profile_directory, &paths, &trust, &policy)?;
        let root_artifact = RootBootstrapArtifact::load()?;
        current_executor_admission(&paths, &executor, &root_artifact, &admission)?;
        let admission = refresh_retained_admission_at(
            profile_directory,
            &paths,
            &trust,
            &policy,
            &admission,
            now()?,
        )?;
        current_executor_admission(&paths, &executor, &root_artifact, &admission)?;
        Some(Self {
            paths,
            executor,
            root_artifact,
            admission,
            profile_directory: profile_directory.to_path_buf(),
        })
    }

    /// Revalidates the retained package member, signed journals, pins, and self identity.
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
        current_executor_admission(&self.paths, &self.executor, &self.root_artifact, &admission)?;
        Some(Self { admission, ..self })
    }

    /// Builds the fixed root-consume endpoint only after fresh executor admission.
    #[must_use]
    pub fn root_consume_configuration(
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
            .root_consume_configuration()
            .ok()?;
        Some((fresh, configuration))
    }

    /// Builds the desktop bootstrap listener endpoint only after fresh admission.
    #[must_use]
    pub fn desktop_bootstrap_configuration(
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

    /// Builds the runtime bootstrap listener endpoint only after fresh admission.
    #[must_use]
    pub fn runtime_bootstrap_configuration(
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
            .runtime_bootstrap_configuration()
            .ok()?;
        Some((fresh, configuration))
    }

    /// Confirms the root-prepared binding against a fresh executor admission.
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

fn current_executor_admission(
    paths: &NativeEnrollmentArtifactPathsV1,
    executor: &OpenedNativeEnrollmentFile,
    root_artifact: &RootBootstrapArtifact,
    admission: &NativeEnrollmentTupleAdmission,
) -> Option<()> {
    matches!(
        admission.qualification(),
        NativeEnrollmentQualification::Unqualified
    )
    .then_some(())?;
    let pins = admission.bootstrap_client_pins.as_ref()?;
    paths.confirm_current_gui_executor(executor).ok()?;
    pins.confirm_current_executor(executor).ok()?;
    pins.confirm_root_artifact(root_artifact)
}

fn now() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::VerifiedInstalledQualificationGuiExecutor;

    #[test]
    fn current_test_binary_outside_fixed_runne_package_is_rejected() {
        assert!(
            VerifiedInstalledQualificationGuiExecutor::admit_current_for_gui_executor(
                std::path::Path::new("/")
            )
            .is_none()
        );
    }
}
