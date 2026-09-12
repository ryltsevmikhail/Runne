use serde::{Deserialize, Serialize};

use super::qualification_bootstrap_client::QualificationBootstrapClientV1;
use super::tuple::NativeEnrollmentTupleV2;
use super::tuple_v3::NativeEnrollmentTupleV3;

pub(super) const SCHEMA_VERSION: u32 = 2;
pub(super) const MAX_ROLE_BYTES: usize = 512 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateSignatureV2 {
    pub key_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateRootRoleV2 {
    pub schema_version: u32,
    pub version: u64,
    pub threshold: u32,
    pub key_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateTargetV2 {
    pub product_id: String,
    pub version: String,
    pub platform: String,
    pub arch: String,
    pub artifact_sha256: String,
    pub artifact_size: u64,
    pub artifact_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub release_candidate_sha256: String,
    pub min_os: String,
    pub profile_id: String,
    pub bundle_sha256: String,
    pub runtime_version: String,
    pub runtime_digest: String,
    pub channel: String,
    pub published_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub rollback_floor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_enrollment_tuple: Option<NativeEnrollmentTupleV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_enrollment_tuple_v3: Option<NativeEnrollmentTupleV3>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualification_bootstrap_client_v1: Option<QualificationBootstrapClientV1>,
}

impl UpdateTargetV2 {
    pub(super) fn native_enrollment_tuples_valid(&self) -> bool {
        let tuples_valid = match (
            self.native_enrollment_tuple.as_ref(),
            self.native_enrollment_tuple_v3.as_ref(),
        ) {
            (None, None) => true,
            (Some(tuple), None) => tuple.valid_signed(self),
            (None, Some(tuple)) => tuple.valid_signed(self),
            (Some(_), Some(_)) => false,
        };
        tuples_valid
            && self
                .qualification_bootstrap_client_v1
                .as_ref()
                .is_none_or(|client| {
                    self.native_enrollment_tuple_v3
                        .as_ref()
                        .is_some_and(|tuple| client.valid_for_v3(tuple))
                })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateTargetsRoleV2 {
    pub version: u64,
    pub expires_at_unix_seconds: u64,
    pub target: UpdateTargetV2,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateSnapshotRoleV2 {
    pub version: u64,
    pub expires_at_unix_seconds: u64,
    pub targets_version: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateTimestampRoleV2 {
    pub version: u64,
    pub expires_at_unix_seconds: u64,
    pub snapshot_version: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateMetadataV2 {
    pub schema_version: u32,
    pub root: UpdateRootRoleV2,
    pub targets: UpdateTargetsRoleV2,
    pub snapshot: UpdateSnapshotRoleV2,
    pub timestamp: UpdateTimestampRoleV2,
    pub root_signatures: Vec<UpdateSignatureV2>,
    pub targets_signatures: Vec<UpdateSignatureV2>,
    pub snapshot_signature: String,
    pub timestamp_signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct UpdateTrustedKeyV2 {
    pub(super) key_id: String,
    pub(super) public_key: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateTrustRootV2 {
    pub(super) root_keys: Vec<UpdateTrustedKeyV2>,
    pub(super) timestamp_key: UpdateTrustedKeyV2,
    pub(super) snapshot_key: UpdateTrustedKeyV2,
}

impl UpdateTrustRootV2 {
    #[must_use]
    pub fn from_keys(
        root_keys: [(&str, [u8; 32]); 3],
        timestamp_key: (&str, [u8; 32]),
        snapshot_key: (&str, [u8; 32]),
    ) -> Self {
        Self {
            root_keys: root_keys.into_iter().map(trusted_key).collect(),
            timestamp_key: trusted_key(timestamp_key),
            snapshot_key: trusted_key(snapshot_key),
        }
    }
}

impl UpdateRootRoleV2 {
    #[must_use]
    pub fn from_trust(trust: &UpdateTrustRootV2, version: u64) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            version,
            threshold: 2,
            key_ids: trust
                .root_keys
                .iter()
                .map(|key| key.key_id.clone())
                .collect(),
        }
    }
}

fn trusted_key((key_id, public_key): (&str, [u8; 32])) -> UpdateTrustedKeyV2 {
    UpdateTrustedKeyV2 {
        key_id: key_id.to_owned(),
        public_key,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateMetadataSigningError {
    InvalidRole,
    TooLarge,
}

impl std::fmt::Display for UpdateMetadataSigningError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRole => "update metadata role serialization failed",
            Self::TooLarge => "update metadata role exceeds its bound",
        })
    }
}

impl std::error::Error for UpdateMetadataSigningError {}

pub fn update_metadata_signing_bytes<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, UpdateMetadataSigningError> {
    let bytes = serde_json::to_vec(value).map_err(|_| UpdateMetadataSigningError::InvalidRole)?;
    (bytes.len() <= MAX_ROLE_BYTES)
        .then_some(bytes)
        .ok_or(UpdateMetadataSigningError::TooLarge)
}
