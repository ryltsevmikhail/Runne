use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use runne_platform_ports::provider_credential_broker::{
    VerifiedWriterArtifact, VerifiedWriterArtifactError,
};
use sha2::{Digest, Sha256};

use super::{
    MeasuredNativeEnrollmentArtifactsV1, NativeEnrollmentQualification, NativeEnrollmentTupleV2,
    UpdateTargetV2, VerifiedMacOsWriterLaunch, VerifiedUpdateV2, macos_identity, matches_installed,
};

/// Non-serializable installed-package admission minted only by `VerifiedUpdateV2`.
#[derive(Debug, Eq, PartialEq)]
pub struct NativeEnrollmentTupleAdmission {
    pub(super) desktop_sha256: [u8; 32],
    pub(super) writer_sha256: [u8; 32],
    pub(super) daemon_sha256: [u8; 32],
    pub(super) release_tuple_sha256: [u8; 32],
    pub(super) candidate_source_sha256: Option<[u8; 32]>,
    pub(super) target_manifest_sha256: Option<[u8; 32]>,
    pub(super) qualification: NativeEnrollmentQualification,
    pub(super) macos_desktop_code_identity: Option<macos_identity::MacOsCodeIdentityV1>,
    pub(super) macos_writer_code_identity: Option<macos_identity::MacOsCodeIdentityV1>,
    pub(super) macos_daemon_code_identity: Option<macos_identity::MacOsCodeIdentityV1>,
}

impl VerifiedUpdateV2 {
    #[must_use]
    pub const fn target(&self) -> &UpdateTargetV2 {
        self.signed.target()
    }

    #[must_use]
    pub(crate) const fn metadata(&self) -> &super::UpdateMetadataV2 {
        self.signed.metadata()
    }

    #[must_use]
    pub const fn native_enrollment_tuple(&self) -> Option<&NativeEnrollmentTupleV2> {
        self.signed.target().native_enrollment_tuple.as_ref()
    }

    #[must_use]
    pub fn admit_native_enrollment(
        &self,
        artifacts: &MeasuredNativeEnrollmentArtifactsV1,
    ) -> Option<NativeEnrollmentTupleAdmission> {
        let tuple = self.signed.native_enrollment_tuple()?;
        let installed_matches = matches_installed(tuple, artifacts);
        if !installed_matches {
            return None;
        }
        let candidate = self.signed.qualified_release_candidate();
        let qualification = NativeEnrollmentQualification::from_candidate(candidate, true);
        let [desktop, writer, daemon] = [
            tuple
                .desktop_code_identity()
                .map(macos_identity::MacOsCodeIdentityV1::from_expectation),
            tuple
                .writer_code_identity()
                .map(macos_identity::MacOsCodeIdentityV1::from_expectation),
            tuple
                .daemon_code_identity()
                .map(macos_identity::MacOsCodeIdentityV1::from_expectation),
        ];
        Some(NativeEnrollmentTupleAdmission {
            desktop_sha256: tuple.desktop_image_digest(),
            writer_sha256: tuple.writer_image_digest(),
            daemon_sha256: tuple.daemon_image_digest(),
            release_tuple_sha256: candidate.map_or_else(
                || tuple.inner_tuple_digest(),
                runne_api::SignedInstalledReleaseCandidateV2::release_binding_digest,
            ),
            candidate_source_sha256: candidate
                .map(|value| value.native_enrollment_tuple().candidate_digest()),
            target_manifest_sha256: candidate
                .map(runne_api::SignedInstalledReleaseCandidateV2::target_manifest_digest),
            qualification,
            macos_desktop_code_identity: desktop,
            macos_writer_code_identity: writer,
            macos_daemon_code_identity: daemon,
        })
    }

    #[must_use]
    pub fn qualify_native_enrollment(
        &self,
        artifacts: &MeasuredNativeEnrollmentArtifactsV1,
    ) -> NativeEnrollmentQualification {
        let installed_matches = self
            .signed
            .native_enrollment_tuple()
            .is_some_and(|tuple| matches_installed(tuple, artifacts));
        NativeEnrollmentQualification::from_candidate(
            self.signed.qualified_release_candidate(),
            installed_matches,
        )
    }
}

impl NativeEnrollmentTupleAdmission {
    #[must_use]
    pub const fn qualification(&self) -> &NativeEnrollmentQualification {
        &self.qualification
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

fn measure_regular_file(path: &Path) -> Option<[u8; 32]> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return None;
    }
    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut chunk).ok()?;
        if read == 0 {
            return Some(hasher.finalize().into());
        }
        hasher.update(&chunk[..read]);
    }
}
