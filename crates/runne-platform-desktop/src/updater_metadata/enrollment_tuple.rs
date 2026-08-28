use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use runne_platform_ports::provider_credential_broker::{
    VerifiedWriterArtifact, VerifiedWriterArtifactError,
};
use sha2::{Digest, Sha256};

/// Signed bindings for the four native artifacts required by credential
/// enrollment. It is evidence only; absence is deliberately unqualified.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[expect(
    clippy::struct_field_names,
    reason = "signed wire fields make their digest algorithm explicit"
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeEnrollmentTupleV1 {
    candidate_sha256: String,
    writer_sha256: String,
    daemon_sha256: String,
    contract_sha256: String,
    tuple_sha256: String,
}

impl NativeEnrollmentTupleV1 {
    /// Builds a self-bound tuple for a target that will be threshold-signed.
    pub fn new(
        candidate_sha256: String,
        writer_sha256: String,
        daemon_sha256: String,
        contract_sha256: String,
        target: &UpdateTargetV2,
    ) -> Result<Self, NativeEnrollmentTupleError> {
        let mut tuple = Self {
            candidate_sha256,
            writer_sha256,
            daemon_sha256,
            contract_sha256,
            tuple_sha256: String::new(),
        };
        if !tuple.matches_target(target) {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        tuple.tuple_sha256 = tuple.digest_for(target);
        Ok(tuple)
    }

    /// Matches signed role bindings to independently measured installed bytes.
    #[must_use]
    pub fn matches_installed(
        &self,
        target: &UpdateTargetV2,
        artifacts: &MeasuredNativeEnrollmentArtifactsV1,
    ) -> bool {
        self.matches_target(target)
            && artifacts.desktop_sha256 == target.artifact_sha256
            && artifacts.writer_sha256 == self.writer_sha256
            && artifacts.daemon_sha256 == self.daemon_sha256
            && artifacts.contract_sha256 == self.contract_sha256
    }

    /// Admits only an exact signed tuple that matches the independently
    /// measured installed package. Absence or any mismatch remains closed.
    #[must_use]
    pub fn qualify(
        &self,
        target: &UpdateTargetV2,
        artifacts: &MeasuredNativeEnrollmentArtifactsV1,
    ) -> NativeEnrollmentQualification {
        let binding = self.matches_installed(target, artifacts).then(|| {
            decode_digest(&self.writer_sha256)
                .zip(decode_digest(&self.tuple_sha256))
                .map(
                    |(writer_sha256, release_tuple_sha256)| NativeEnrollmentQualificationBinding {
                        writer_sha256,
                        release_tuple_sha256,
                    },
                )
        });
        match binding {
            Some(Some(binding)) => NativeEnrollmentQualification::Qualified(binding),
            _ => NativeEnrollmentQualification::Unqualified,
        }
    }

    fn matches_target(&self, target: &UpdateTargetV2) -> bool {
        digests_valid([
            self.candidate_sha256.as_str(),
            self.writer_sha256.as_str(),
            self.daemon_sha256.as_str(),
            self.contract_sha256.as_str(),
            target.artifact_sha256.as_str(),
        ]) && self.candidate_sha256 == target.release_candidate_sha256
            && self.contract_sha256 == target.bundle_sha256
            && all_distinct([
                self.writer_sha256.as_str(),
                self.daemon_sha256.as_str(),
                self.contract_sha256.as_str(),
                target.artifact_sha256.as_str(),
            ])
            && (self.tuple_sha256.is_empty() || self.tuple_sha256 == self.digest_for(target))
    }

    fn digest_for(&self, target: &UpdateTargetV2) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"gocode/native-enrollment-release-tuple/v1\0");
        for value in [
            self.candidate_sha256.as_str(),
            target.product_id.as_str(),
            target.version.as_str(),
            target.platform.as_str(),
            target.arch.as_str(),
            target.profile_id.as_str(),
            target.artifact_sha256.as_str(),
            self.writer_sha256.as_str(),
            self.daemon_sha256.as_str(),
            self.contract_sha256.as_str(),
        ] {
            hasher.update(u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
            hasher.update(value.as_bytes());
        }
        hex::encode(hasher.finalize())
    }
}

/// Closed release admission state for the native credential flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeEnrollmentQualification {
    Unqualified,
    Qualified(NativeEnrollmentQualificationBinding),
}

impl NativeEnrollmentQualification {
    /// Re-measures a staged regular writer before yielding an artifact usable
    /// by the direct native launcher. Paths, symlinks and metadata alone never
    /// establish trust.
    pub fn verified_writer(
        self,
        executable: PathBuf,
    ) -> Result<VerifiedWriterArtifact, VerifiedWriterArtifactError> {
        let Self::Qualified(binding) = self else {
            return Err(VerifiedWriterArtifactError::Unavailable);
        };
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
}

/// Non-serializable binding carried from release admission to native launch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeEnrollmentQualificationBinding {
    writer_sha256: [u8; 32],
    release_tuple_sha256: [u8; 32],
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

fn decode_digest(value: &str) -> Option<[u8; 32]> {
    hex::decode(value).ok()?.try_into().ok()
}

/// Independently measured installed artifacts. This contains no paths or
/// process identity, so callers cannot turn a location into package trust.
#[derive(Clone, Debug, Eq, PartialEq)]
#[expect(
    clippy::struct_field_names,
    reason = "measured artifact fields make their digest algorithm explicit"
)]
pub struct MeasuredNativeEnrollmentArtifactsV1 {
    desktop_sha256: String,
    writer_sha256: String,
    daemon_sha256: String,
    contract_sha256: String,
}

impl MeasuredNativeEnrollmentArtifactsV1 {
    pub fn new(
        desktop_sha256: String,
        writer_sha256: String,
        daemon_sha256: String,
        contract_sha256: String,
    ) -> Result<Self, NativeEnrollmentTupleError> {
        let values = [
            desktop_sha256.as_str(),
            writer_sha256.as_str(),
            daemon_sha256.as_str(),
            contract_sha256.as_str(),
        ];
        if !digests_valid(values) || !all_distinct(values) {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        Ok(Self {
            desktop_sha256,
            writer_sha256,
            daemon_sha256,
            contract_sha256,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeEnrollmentTupleError {
    Rejected,
}

fn digests_valid<'a>(values: impl IntoIterator<Item = &'a str>) -> bool {
    values.into_iter().all(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

fn all_distinct<'a>(values: impl IntoIterator<Item = &'a str>) -> bool {
    let values: Vec<_> = values.into_iter().collect();
    values
        .iter()
        .enumerate()
        .all(|(index, value)| values[..index].iter().all(|prior| prior != value))
}
