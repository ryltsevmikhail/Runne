use std::path::PathBuf;

use runne_platform_ports::provider_credential_broker::{
    VerifiedWriterArtifact, VerifiedWriterArtifactError,
};

use super::super::VerifiedMacOsWriterLaunch;
use super::{NativeEnrollmentTupleAdmission, measure_regular_file};
use crate::NativeEnrollmentQualification;

impl NativeEnrollmentTupleAdmission {
    #[cfg(test)]
    pub(crate) const fn test_only_raw_v3_tuple_sha256(&self) -> Option<[u8; 32]> {
        self.raw_v3_tuple_sha256
    }

    #[cfg(test)]
    pub(crate) const fn test_only_release_tuple_sha256(&self) -> [u8; 32] {
        self.release_tuple_sha256
    }

    #[cfg(any(test, target_os = "macos"))]
    #[must_use]
    pub(crate) const fn installed_generation(&self) -> u64 {
        self.installed_generation
    }

    #[must_use]
    pub const fn qualification(&self) -> &NativeEnrollmentQualification {
        &self.qualification
    }

    #[cfg(all(feature = "test-support", target_os = "macos"))]
    pub(crate) fn with_local_code_identities(
        mut self,
        paths: &super::super::NativeEnrollmentArtifactPathsV1,
    ) -> Option<Self> {
        if !runne_api::test_support::local_native_enrollment_enabled() {
            return None;
        }
        let desktop = super::super::macos_identity::MacOsCodeIdentityV1::local(
            &paths.desktop,
            "dev.runne.slice-e.desktop",
        )?;
        let writer_path = paths.writer_executable_path();
        let writer = super::super::macos_identity::MacOsCodeIdentityV1::local(
            &writer_path,
            "dev.runne.slice-e.writer",
        )?;
        let daemon_path = paths.desktop.parent()?.join("runned");
        let daemon = super::super::macos_identity::MacOsCodeIdentityV1::local(
            &daemon_path,
            "dev.runne.slice-e.daemon",
        )?;
        if desktop == writer || desktop == daemon || writer == daemon {
            return None;
        }
        self.bootstrap_client_pins = None;
        self.macos_desktop_code_identity = Some(desktop);
        self.macos_writer_code_identity = Some(writer);
        self.macos_daemon_code_identity = Some(daemon);
        let service_path = paths.desktop.parent()?.parent()?.join(
            "Library/Helpers/RunneCredentialService.app/Contents/MacOS/runne-credential-service",
        );
        if service_path.exists() {
            let service = super::super::macos_identity::MacOsCodeIdentityV1::local(
                &service_path,
                "dev.runne.slice-e.credential-service",
            )?;
            if self
                .macos_desktop_code_identity
                .as_ref()
                .is_some_and(|identity| identity == &service)
                || self
                    .macos_writer_code_identity
                    .as_ref()
                    .is_some_and(|identity| identity == &service)
                || self
                    .macos_daemon_code_identity
                    .as_ref()
                    .is_some_and(|identity| identity == &service)
            {
                return None;
            }
            self.credential_service_sha256 = Some(measure_regular_file(&service_path)?);
            self.macos_credential_service_code_identity = Some(service);
        }
        Some(self)
    }

    pub fn verified_writer(
        &self,
        executable: PathBuf,
    ) -> Result<VerifiedWriterArtifact, VerifiedWriterArtifactError> {
        self.macos_writer_code_identity
            .is_none()
            .then_some(())
            .ok_or(VerifiedWriterArtifactError::Rejected)?;
        self.verified_writer_artifact(executable)
    }

    pub fn verified_macos_writer(
        &self,
        executable: PathBuf,
    ) -> Result<VerifiedMacOsWriterLaunch, VerifiedWriterArtifactError> {
        let writer = self
            .macos_writer_code_identity
            .as_ref()
            .ok_or(VerifiedWriterArtifactError::Rejected)?;
        let desktop = self
            .macos_desktop_code_identity
            .as_ref()
            .filter(|desktop| *desktop != writer)
            .ok_or(VerifiedWriterArtifactError::Rejected)?;
        let daemon = self
            .macos_daemon_code_identity
            .as_ref()
            .filter(|daemon| *daemon != writer && *daemon != desktop)
            .ok_or(VerifiedWriterArtifactError::Rejected)?;
        let artifact = self.verified_writer_artifact(executable)?;
        Ok(VerifiedMacOsWriterLaunch::new(
            artifact,
            writer,
            self.daemon_sha256,
            daemon,
        ))
    }

    fn verified_writer_artifact(
        &self,
        executable: PathBuf,
    ) -> Result<VerifiedWriterArtifact, VerifiedWriterArtifactError> {
        let measured =
            measure_regular_file(&executable).ok_or(VerifiedWriterArtifactError::Rejected)?;
        (measured == self.writer_sha256)
            .then_some(())
            .ok_or(VerifiedWriterArtifactError::Rejected)?;
        VerifiedWriterArtifact::new(executable, self.writer_sha256, self.release_tuple_sha256)
    }
}
