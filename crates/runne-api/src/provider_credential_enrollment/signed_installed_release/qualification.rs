use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::model::UpdateTargetV2;
use super::tuple::{NativeEnrollmentTupleError, NativeEnrollmentTupleV2, digest_valid};

const QUALIFICATION_DOMAIN: &[u8] = b"gocode/native-enrollment-qualification-binding/v1\0";

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
        row.valid_shape(target, tuple)
            .then_some(())
            .ok_or(NativeEnrollmentTupleError::Rejected)?;
        row.binding_sha256 = row.digest_for(target, tuple);
        Ok(row)
    }

    pub(super) fn valid_binding(
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
            && target.platform == "macos"
            && matches!(target.arch.as_str(), "arm64" | "aarch64")
            && target
                .artifact_url
                .split(['?', '#'])
                .next()
                .is_some_and(|url| url.ends_with(".dmg"))
            && digest_valid(&self.receipt_sha256)
            && self.qualified_at_unix_seconds != 0
            && self.qualified_at_unix_seconds < self.expires_at_unix_seconds
            && self.expires_at_unix_seconds <= target.expires_at_unix_seconds
            && tuple.tuple_digest().is_some()
            && tuple.digest_for(target) == hex::encode(tuple.tuple_digest().unwrap_or_default())
    }

    fn digest_for(&self, target: &UpdateTargetV2, tuple: &NativeEnrollmentTupleV2) -> String {
        let mut hasher = Sha256::new();
        hasher.update(QUALIFICATION_DOMAIN);
        for value in [
            hex::encode(tuple.tuple_digest().unwrap_or_default()).as_str(),
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

    pub(super) fn receipt_digest(&self) -> Option<[u8; 32]> {
        super::tuple::decode_digest(&self.receipt_sha256)
    }
    pub(super) fn binding_digest(&self) -> Option<[u8; 32]> {
        super::tuple::decode_digest(&self.binding_sha256)
    }
    pub(super) const fn qualified_at(&self) -> u64 {
        self.qualified_at_unix_seconds
    }
    pub(super) const fn expires_at(&self) -> u64 {
        self.expires_at_unix_seconds
    }
}

impl NativeEnrollmentTupleV2 {
    pub fn with_qualification(
        mut self,
        target: &UpdateTargetV2,
        qualification: NativeEnrollmentQualificationRowV1,
    ) -> Result<Self, NativeEnrollmentTupleError> {
        qualification
            .valid_binding(target, &self)
            .then_some(())
            .ok_or(NativeEnrollmentTupleError::Rejected)?;
        self.set_qualification(qualification);
        Ok(self)
    }
}
