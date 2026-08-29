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
pub use enrollment_qualification::NativeEnrollmentQualification;
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

pub fn verify_update_v2(
    metadata: &UpdateMetadataV2,
    trust: &UpdateTrustRootV2,
    binding: &UpdateTargetV2Binding<'_>,
    now_unix_seconds: u64,
    current_version: &str,
    rollback_floor: &str,
) -> Result<VerifiedUpdateV2, UpdateV2VerificationError> {
    if metadata.schema_version != SCHEMA_VERSION
        || metadata.targets.version == 0
        || metadata.snapshot.version == 0
        || metadata.timestamp.version == 0
        || metadata.snapshot.targets_version != metadata.targets.version
        || metadata.timestamp.snapshot_version != metadata.snapshot.version
        || !root_matches(&metadata.root, trust)
    {
        return Err(UpdateV2VerificationError::InvalidMetadata);
    }
    verify_quorum(
        &metadata.root_signatures,
        &trust.root_keys,
        &metadata.root,
        ROOT_THRESHOLD,
    )
    .map_err(|()| UpdateV2VerificationError::RootQuorum)?;
    verify_quorum(
        &metadata.targets_signatures,
        &trust.root_keys,
        &metadata.targets,
        ROOT_THRESHOLD,
    )
    .map_err(|()| UpdateV2VerificationError::TargetsQuorum)?;
    verify_single(
        &metadata.snapshot_signature,
        &trust.snapshot_key,
        &metadata.snapshot,
    )
    .map_err(|()| UpdateV2VerificationError::SnapshotSignature)?;
    verify_single(
        &metadata.timestamp_signature,
        &trust.timestamp_key,
        &metadata.timestamp,
    )
    .map_err(|()| UpdateV2VerificationError::TimestampSignature)?;
    let target = &metadata.targets.target;
    if metadata.targets.expires_at_unix_seconds <= now_unix_seconds
        || metadata.snapshot.expires_at_unix_seconds <= now_unix_seconds
        || metadata.timestamp.expires_at_unix_seconds <= now_unix_seconds
        || target.expires_at_unix_seconds <= now_unix_seconds
        || target.published_at_unix_seconds > now_unix_seconds
    {
        return Err(UpdateV2VerificationError::Expired);
    }
    if !target_matches(target, binding) {
        return Err(UpdateV2VerificationError::TargetMismatch);
    }
    if target.artifact_size == 0
        || target.artifact_size > MAX_ARTIFACT_BYTES
        || !crate::updater::is_sha256(&target.artifact_sha256)
        || !crate::updater::is_sha256(&target.bundle_sha256)
        || !crate::updater::is_sha256(&target.runtime_digest)
        || !crate::updater_feed::is_https_url(&target.artifact_url)
    {
        return Err(UpdateV2VerificationError::InvalidMetadata);
    }
    if target
        .native_enrollment_tuple
        .as_ref()
        .is_some_and(|tuple| !tuple.matches_target(target))
    {
        return Err(UpdateV2VerificationError::InvalidMetadata);
    }
    let artifact_kind = crate::UpdateArtifactKind::from_url(&target.artifact_url)
        .map_err(|_| UpdateV2VerificationError::InvalidMetadata)?;
    if !artifact_kind.supports_platform(&target.platform) {
        return Err(UpdateV2VerificationError::InvalidMetadata);
    }
    let version = crate::updater::parse_version(&target.version)
        .map_err(|_| UpdateV2VerificationError::InvalidMetadata)?;
    let current = crate::updater::parse_version(current_version)
        .map_err(|_| UpdateV2VerificationError::InvalidMetadata)?;
    let floor = crate::updater::parse_version(rollback_floor)
        .map_err(|_| UpdateV2VerificationError::InvalidMetadata)?;
    let target_floor = crate::updater::parse_version(&target.rollback_floor)
        .map_err(|_| UpdateV2VerificationError::InvalidMetadata)?;
    if version < current || version < floor || target_floor < floor {
        return Err(UpdateV2VerificationError::Rollback);
    }
    Ok(VerifiedUpdateV2 {
        metadata: metadata.clone(),
    })
}

include!("updater_metadata/verification.rs");
