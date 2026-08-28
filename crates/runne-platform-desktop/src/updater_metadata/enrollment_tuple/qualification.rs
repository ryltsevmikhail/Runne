use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use runne_platform_ports::provider_credential_broker::{
    VerifiedWriterArtifact, VerifiedWriterArtifactError,
};
use sha2::{Digest, Sha256};

use super::{VerifiedMacOsWriterLaunch, macos_identity};

/// Closed release admission state for the native credential flow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeEnrollmentQualification {
    Unqualified,
    Qualified(NativeEnrollmentQualificationBinding),
}

impl NativeEnrollmentQualification {
    /// Re-measures a staged regular non-macOS writer before yielding an artifact.
    pub fn verified_writer(
        &self,
        executable: PathBuf,
    ) -> Result<VerifiedWriterArtifact, VerifiedWriterArtifactError> {
        let Self::Qualified(binding) = self else {
            return Err(VerifiedWriterArtifactError::Unavailable);
        };
        if binding.macos_writer_code_identity.is_some() {
            return Err(VerifiedWriterArtifactError::Rejected);
        }
        verified_writer_artifact(binding, executable)
    }

    /// Re-measures one macOS writer and retains its signed code requirement.
    pub fn verified_macos_writer(
        &self,
        executable: PathBuf,
    ) -> Result<VerifiedMacOsWriterLaunch, VerifiedWriterArtifactError> {
        let Self::Qualified(binding) = self else {
            return Err(VerifiedWriterArtifactError::Unavailable);
        };
        let identity = binding
            .macos_writer_code_identity
            .clone()
            .ok_or(VerifiedWriterArtifactError::Rejected)?;
        let artifact = verified_writer_artifact(binding, executable)?;
        Ok(VerifiedMacOsWriterLaunch::new(artifact, &identity))
    }
}

fn verified_writer_artifact(
    binding: &NativeEnrollmentQualificationBinding,
    executable: PathBuf,
) -> Result<VerifiedWriterArtifact, VerifiedWriterArtifactError> {
    let measured =
        measure_regular_file(&executable).ok_or(VerifiedWriterArtifactError::Rejected)?;
    (measured == binding.writer_sha256)
        .then_some(())
        .ok_or(VerifiedWriterArtifactError::Rejected)?;
    VerifiedWriterArtifact::new(
        executable,
        binding.writer_sha256,
        binding.release_tuple_sha256,
    )
}

/// Non-serializable binding carried from release admission to native launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeEnrollmentQualificationBinding {
    pub(super) writer_sha256: [u8; 32],
    pub(super) release_tuple_sha256: [u8; 32],
    pub(super) macos_writer_code_identity: Option<macos_identity::MacOsWriterCodeIdentityV1>,
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
