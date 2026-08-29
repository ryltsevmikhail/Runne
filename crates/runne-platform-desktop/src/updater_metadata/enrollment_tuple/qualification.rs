use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{NativeEnrollmentTupleError, NativeEnrollmentTupleV2, UpdateTargetV2};

const BINDING_DOMAIN: &[u8] = b"gocode/native-enrollment-qualification-binding/v1\0";

/// A pre-signing structural row, not authority to enable enrollment.
///
/// Only `VerifiedUpdateV2` can combine this signed row with measured installed
/// artifacts and mint `NativeEnrollmentQualification::Qualified`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeEnrollmentQualificationRowV1 {
    schema_version: u32,
    platform: String,
    architecture: String,
    package_kind: String,
    receipt_sha256: String,
    qualified_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    binding_sha256: String,
}

impl NativeEnrollmentQualificationRowV1 {
    /// Builds a self-bound row for threshold signing; this is not authority.
    pub fn new(
        target: &UpdateTargetV2,
        tuple: &NativeEnrollmentTupleV2,
        receipt_sha256: String,
        qualified_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<Self, NativeEnrollmentTupleError> {
        let mut row = Self {
            schema_version: 1,
            platform: "macos".into(),
            architecture: "arm64".into(),
            package_kind: "dmg".into(),
            receipt_sha256,
            qualified_at_unix_seconds,
            expires_at_unix_seconds,
            binding_sha256: String::new(),
        };
        if !row.valid_shape(target, tuple) {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        row.binding_sha256 = row.digest_for(target, tuple);
        Ok(row)
    }

    pub(super) fn matches_target(
        &self,
        target: &UpdateTargetV2,
        tuple: &NativeEnrollmentTupleV2,
    ) -> bool {
        self.valid_shape(target, tuple) && self.binding_sha256 == self.digest_for(target, tuple)
    }

    fn valid_shape(&self, target: &UpdateTargetV2, tuple: &NativeEnrollmentTupleV2) -> bool {
        self.schema_version == 1
            && self.platform == "macos"
            && self.architecture == "arm64"
            && self.package_kind == "dmg"
            && super::digests_valid([self.receipt_sha256.as_str()])
            && self.qualified_at_unix_seconds != 0
            && self.qualified_at_unix_seconds < self.expires_at_unix_seconds
            && self.expires_at_unix_seconds <= target.expires_at_unix_seconds
            && target.platform == "macos"
            && matches!(target.arch.as_str(), "arm64" | "aarch64")
            && crate::UpdateArtifactKind::from_url(&target.artifact_url)
                .is_ok_and(|kind| kind == crate::UpdateArtifactKind::MacDmg)
            && tuple.base_matches_target(target)
            && super::digests_valid([tuple.tuple_sha256.as_str()])
            && tuple.tuple_sha256 == tuple.digest_for(target)
    }

    fn digest_for(&self, target: &UpdateTargetV2, tuple: &NativeEnrollmentTupleV2) -> String {
        let mut hasher = Sha256::new();
        hasher.update(BINDING_DOMAIN);
        for value in [
            tuple.tuple_sha256.as_str(),
            target.product_id.as_str(),
            target.version.as_str(),
            target.platform.as_str(),
            target.arch.as_str(),
            target.profile_id.as_str(),
            target.artifact_sha256.as_str(),
            self.platform.as_str(),
            self.architecture.as_str(),
            self.package_kind.as_str(),
            self.receipt_sha256.as_str(),
        ] {
            hasher.update(u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
            hasher.update(value.as_bytes());
        }
        hasher.update(self.qualified_at_unix_seconds.to_be_bytes());
        hasher.update(self.expires_at_unix_seconds.to_be_bytes());
        hex::encode(hasher.finalize())
    }
}

impl NativeEnrollmentTupleV2 {
    /// Adds a pre-signing qualification row without changing the base tuple digest.
    pub fn with_qualification(
        mut self,
        target: &UpdateTargetV2,
        qualification: NativeEnrollmentQualificationRowV1,
    ) -> Result<Self, NativeEnrollmentTupleError> {
        if !qualification.matches_target(target, &self) {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        self.native_enrollment_qualification = Some(qualification);
        Ok(self)
    }

    pub(super) fn qualification_for(
        &self,
        target: &UpdateTargetV2,
        artifacts: &super::MeasuredNativeEnrollmentArtifactsV1,
        verified_at_unix_seconds: u64,
    ) -> NativeEnrollmentQualification {
        let Some(qualification) = self.native_enrollment_qualification.as_ref() else {
            return NativeEnrollmentQualification::Unqualified;
        };
        if !self.matches_installed(target, artifacts)
            || !qualification.matches_target(target, self)
            || qualification.qualified_at_unix_seconds > verified_at_unix_seconds
            || verified_at_unix_seconds >= qualification.expires_at_unix_seconds
        {
            return NativeEnrollmentQualification::Unqualified;
        }
        let Some(release_tuple_sha256) = decode_digest(&self.tuple_sha256) else {
            return NativeEnrollmentQualification::Unqualified;
        };
        let Some(binding_sha256) = decode_digest(&qualification.binding_sha256) else {
            return NativeEnrollmentQualification::Unqualified;
        };
        NativeEnrollmentQualification::qualified(
            release_tuple_sha256,
            binding_sha256,
            qualification.expires_at_unix_seconds,
        )
    }
}

fn decode_digest(value: &str) -> Option<[u8; 32]> {
    hex::decode(value).ok()?.try_into().ok()
}

/// Qualification state produced only from verified metadata and measured bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeEnrollmentQualification {
    Unqualified,
    Qualified(NativeEnrollmentQualificationBinding),
}

/// Opaque non-serializable binding retained for later exact composition checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeEnrollmentQualificationBinding {
    release_tuple_sha256: [u8; 32],
    qualification_binding_sha256: [u8; 32],
    expires_at_unix_seconds: u64,
}

impl NativeEnrollmentQualification {
    const fn qualified(
        release_tuple_sha256: [u8; 32],
        qualification_binding_sha256: [u8; 32],
        expires_at_unix_seconds: u64,
    ) -> Self {
        Self::Qualified(NativeEnrollmentQualificationBinding {
            release_tuple_sha256,
            qualification_binding_sha256,
            expires_at_unix_seconds,
        })
    }

    /// Checks the opaque binding without granting launch or route authority.
    #[must_use]
    pub fn matches_exact(
        &self,
        release_tuple_sha256: [u8; 32],
        qualification_binding_sha256: [u8; 32],
        now_unix_seconds: u64,
    ) -> bool {
        match self {
            Self::Unqualified => false,
            Self::Qualified(binding) => {
                binding.release_tuple_sha256 == release_tuple_sha256
                    && binding.qualification_binding_sha256 == qualification_binding_sha256
                    && now_unix_seconds < binding.expires_at_unix_seconds
            }
        }
    }
}

/// ```compile_fail
/// use runne_platform_desktop::{
///     NativeEnrollmentQualification, NativeEnrollmentQualificationBinding,
/// };
///
/// let binding = NativeEnrollmentQualificationBinding {
///     release_tuple_sha256: [0; 32],
///     qualification_binding_sha256: [0; 32],
///     expires_at_unix_seconds: 1,
/// };
/// let _ = NativeEnrollmentQualification::Qualified(binding);
/// ```
const _: () = ();
