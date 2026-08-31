//! Threshold-signed release metadata verification for the production updater.

#![allow(clippy::missing_errors_doc)]

use std::collections::HashSet;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const SCHEMA_VERSION: u32 = 2;
const ROOT_THRESHOLD: usize = 2;
const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SIGNATURES: usize = 8;

#[path = "updater_metadata/enrollment_tuple/macos_identity.rs"]
mod macos_identity;
pub use macos_identity::VerifiedMacOsWriterLaunch;
#[path = "updater_metadata/enrollment_tuple/qualification.rs"]
mod enrollment_qualification;
pub use enrollment_desktop_peer_claim::EnrollmentTransitionFacts;
pub use enrollment_qualification::{
    NativeEnrollmentQualification, NativeEnrollmentQualificationBinding,
    NativeEnrollmentQualificationRowV1,
};
#[path = "updater_metadata/enrollment_tuple/admission.rs"]
mod enrollment_admission;
pub use enrollment_admission::NativeEnrollmentTupleAdmission;

include!("updater_metadata/enrollment_tuple.rs");

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
pub struct UpdateTrustedKeyV2 {
    pub key_id: String,
    pub public_key: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateTrustRootV2 {
    root_keys: Vec<UpdateTrustedKeyV2>,
    timestamp_key: UpdateTrustedKeyV2,
    snapshot_key: UpdateTrustedKeyV2,
}

impl UpdateTrustRootV2 {
    #[must_use]
    pub fn from_keys(
        root_keys: [(&str, [u8; 32]); 3],
        timestamp_key: (&str, [u8; 32]),
        snapshot_key: (&str, [u8; 32]),
    ) -> Self {
        Self {
            root_keys: root_keys
                .into_iter()
                .map(|(key_id, public_key)| UpdateTrustedKeyV2 {
                    key_id: key_id.to_owned(),
                    public_key,
                })
                .collect(),
            timestamp_key: trusted_key(timestamp_key),
            snapshot_key: trusted_key(snapshot_key),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateTargetV2Binding<'a> {
    pub product_id: &'a str,
    pub platform: &'a str,
    pub arch: &'a str,
    pub min_os: &'a str,
    pub profile_id: &'a str,
    pub bundle_sha256: &'a str,
    pub runtime_version: &'a str,
    pub runtime_digest: &'a str,
    pub channel: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedUpdateV2 {
    metadata: UpdateMetadataV2,
    verified_at_unix_seconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum UpdateV2VerificationError {
    #[error("update metadata is invalid")]
    InvalidMetadata,
    #[error("root signature quorum is insufficient")]
    RootQuorum,
    #[error("targets signature quorum is insufficient")]
    TargetsQuorum,
    #[error("timestamp signature is invalid")]
    TimestampSignature,
    #[error("snapshot signature is invalid")]
    SnapshotSignature,
    #[error("update target does not match this desktop")]
    TargetMismatch,
    #[error("update metadata is expired")]
    Expired,
    #[error("update is below the rollback floor")]
    Rollback,
}

#[path = "updater_metadata/verify_v2.rs"]
mod verify_v2;
pub use verify_v2::verify_update_v2;
#[cfg(all(feature = "dev-loopback-updater", debug_assertions))]
pub use verify_v2::verify_update_v2_dev_loopback;

include!("updater_metadata/verification.rs");
