use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use runne_platform_ports::provider_credential_broker::{
    VerifiedWriterArtifact, VerifiedWriterArtifactError,
};
use sha2::{Digest, Sha256};

use super::{
    MeasuredNativeEnrollmentArtifactsV1, NativeEnrollmentQualification, NativeEnrollmentTupleV2,
    UpdateTargetV2, VerifiedMacOsWriterLaunch, VerifiedUpdateV2, macos_identity,
};

/// Non-serializable installed-package admission minted only by `VerifiedUpdateV2`.
#[derive(Debug, Eq, PartialEq)]
pub struct NativeEnrollmentTupleAdmission {
    pub(super) desktop_sha256: [u8; 32],
    pub(super) writer_sha256: [u8; 32],
    pub(super) daemon_sha256: [u8; 32],
    pub(super) release_tuple_sha256: [u8; 32],
    pub(super) qualification: NativeEnrollmentQualification,
    pub(super) macos_desktop_code_identity: Option<macos_identity::MacOsCodeIdentityV1>,
    pub(super) macos_writer_code_identity: Option<macos_identity::MacOsCodeIdentityV1>,
    pub(super) macos_daemon_code_identity: Option<macos_identity::MacOsCodeIdentityV1>,
}

impl VerifiedUpdateV2 {
    #[must_use]
    pub const fn target(&self) -> &UpdateTargetV2 {
        &self.metadata.targets.target
    }

    #[must_use]
    pub(crate) const fn metadata(&self) -> &super::UpdateMetadataV2 {
        &self.metadata
    }

    #[must_use]
    pub const fn native_enrollment_tuple(&self) -> Option<&NativeEnrollmentTupleV2> {
        self.metadata
            .targets
            .target
            .native_enrollment_tuple
            .as_ref()
    }

    /// Mints admission for exactly one threshold-verified, measured package tuple.
    #[must_use]
    pub fn admit_native_enrollment(
        &self,
        artifacts: &MeasuredNativeEnrollmentArtifactsV1,
    ) -> Option<NativeEnrollmentTupleAdmission> {
        self.metadata
            .targets
            .target
            .native_enrollment_tuple
            .as_ref()
            .and_then(|tuple| tuple.admit(self.target(), artifacts, self.verified_at_unix_seconds))
    }

    /// Qualifies only an exact threshold-signed row and independently measured tuple.
    #[must_use]
    pub fn qualify_native_enrollment(
        &self,
        artifacts: &MeasuredNativeEnrollmentArtifactsV1,
    ) -> NativeEnrollmentQualification {
        self.metadata
            .targets
            .target
            .native_enrollment_tuple
            .as_ref()
            .map_or(NativeEnrollmentQualification::Unqualified, |tuple| {
                tuple.qualification_for(self.target(), artifacts, self.verified_at_unix_seconds)
            })
    }
}

impl NativeEnrollmentTupleV2 {
    fn admit(
        &self,
        target: &UpdateTargetV2,
        artifacts: &MeasuredNativeEnrollmentArtifactsV1,
        verified_at_unix_seconds: u64,
    ) -> Option<NativeEnrollmentTupleAdmission> {
        (self.matches_installed(target, artifacts) && self.tuple_sha256 == self.digest_for(target))
            .then(|| {
                decode_digest(&self.desktop_sha256)
                    .zip(decode_digest(&self.writer_sha256))
                    .zip(decode_digest(&self.daemon_sha256))
                    .zip(decode_digest(&self.tuple_sha256))
            })
            .flatten()
            .map(
                |(((desktop_sha256, writer_sha256), daemon_sha256), release_tuple_sha256)| {
                    NativeEnrollmentTupleAdmission {
                        desktop_sha256,
                        writer_sha256,
                        daemon_sha256,
                        release_tuple_sha256,
                        qualification: self.qualification_for(
                            target,
                            artifacts,
                            verified_at_unix_seconds,
                        ),
                        macos_desktop_code_identity: self.desktop_code_identity.clone(),
                        macos_writer_code_identity: self.writer_code_identity.clone(),
                        macos_daemon_code_identity: self.daemon_code_identity.clone(),
                    }
                },
            )
    }
}

impl NativeEnrollmentTupleAdmission {
    /// Returns the retained non-authoritative qualification state.
    #[must_use]
    pub const fn qualification(&self) -> &NativeEnrollmentQualification {
        &self.qualification
    }

    /// Re-measures a staged non-macOS writer before yielding its exact artifact.
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

    /// Re-measures one macOS writer and retains distinct signed role identities.
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

fn decode_digest(value: &str) -> Option<[u8; 32]> {
    hex::decode(value).ok()?.try_into().ok()
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
