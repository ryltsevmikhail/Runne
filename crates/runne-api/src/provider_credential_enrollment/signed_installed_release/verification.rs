use std::collections::HashSet;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::Serialize;

use super::binding::{
    VerifiedSignedInstalledReleaseV2, VerifiedSignedUpdateMetadataV2, build_verified, exact,
};
use super::model::{
    SCHEMA_VERSION, UpdateMetadataV2, UpdateSignatureV2, UpdateTrustRootV2, UpdateTrustedKeyV2,
    update_metadata_signing_bytes,
};

const MAX_METADATA_BYTES: usize = 512 * 1024;
const ROOT_THRESHOLD: usize = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignedInstalledReleaseVerificationErrorV2 {
    MetadataTooLarge,
    InvalidEncoding,
    NonCanonicalMetadata,
    InvalidTrustRoot,
    InvalidMetadata,
    RootQuorum,
    TargetsQuorum,
    SnapshotSignature,
    TimestampSignature,
    Expired,
    Unqualified,
    ReleaseBindingMismatch,
}

impl std::fmt::Display for SignedInstalledReleaseVerificationErrorV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::MetadataTooLarge => "signed release metadata exceeds its bound",
            Self::InvalidEncoding => "signed release metadata encoding is invalid",
            Self::NonCanonicalMetadata => "signed release metadata is not canonical",
            Self::InvalidTrustRoot => "signed release trust root is invalid",
            Self::InvalidMetadata => "signed release metadata is invalid",
            Self::RootQuorum => "root signature quorum is invalid",
            Self::TargetsQuorum => "targets signature quorum is invalid",
            Self::SnapshotSignature => "snapshot signature is invalid",
            Self::TimestampSignature => "timestamp signature is invalid",
            Self::Expired => "signed release metadata is expired or not current",
            Self::Unqualified => "signed release is not currently qualified",
            Self::ReleaseBindingMismatch => "signed installed-release binding does not match",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SignedInstalledReleaseVerificationErrorV2 {}

pub fn verify_signed_update_metadata_v2(
    metadata: &UpdateMetadataV2,
    trust: &UpdateTrustRootV2,
    now_unix_seconds: u64,
) -> Result<VerifiedSignedUpdateMetadataV2, SignedInstalledReleaseVerificationErrorV2> {
    validate_trust(trust)?;
    validate_structure(metadata, trust, now_unix_seconds)?;
    verify_quorum(
        &metadata.root_signatures,
        &trust.root_keys,
        &metadata.root,
        ROOT_THRESHOLD,
    )
    .map_err(|()| SignedInstalledReleaseVerificationErrorV2::RootQuorum)?;
    verify_quorum(
        &metadata.targets_signatures,
        &trust.root_keys,
        &metadata.targets,
        ROOT_THRESHOLD,
    )
    .map_err(|()| SignedInstalledReleaseVerificationErrorV2::TargetsQuorum)?;
    verify_single(
        &metadata.snapshot_signature,
        &trust.snapshot_key,
        &metadata.snapshot,
    )
    .map_err(|()| SignedInstalledReleaseVerificationErrorV2::SnapshotSignature)?;
    verify_single(
        &metadata.timestamp_signature,
        &trust.timestamp_key,
        &metadata.timestamp,
    )
    .map_err(|()| SignedInstalledReleaseVerificationErrorV2::TimestampSignature)?;
    if !metadata.targets.target.native_enrollment_tuples_valid() {
        return Err(SignedInstalledReleaseVerificationErrorV2::InvalidMetadata);
    }
    build_verified(metadata, now_unix_seconds)
}

pub fn verify_exact_signed_installed_release_v2(
    canonical_metadata: &[u8],
    trust: &UpdateTrustRootV2,
    expected_release_binding: [u8; 32],
    now_unix_seconds: u64,
) -> Result<VerifiedSignedInstalledReleaseV2, SignedInstalledReleaseVerificationErrorV2> {
    let metadata = decode_canonical_metadata(canonical_metadata)?;
    exact(
        verify_signed_update_metadata_v2(&metadata, trust, now_unix_seconds)?,
        expected_release_binding,
    )
}

pub(super) fn decode_canonical_metadata(
    canonical_metadata: &[u8],
) -> Result<UpdateMetadataV2, SignedInstalledReleaseVerificationErrorV2> {
    if canonical_metadata.len() > MAX_METADATA_BYTES {
        return Err(SignedInstalledReleaseVerificationErrorV2::MetadataTooLarge);
    }
    if canonical_metadata.is_empty() {
        return Err(SignedInstalledReleaseVerificationErrorV2::InvalidEncoding);
    }
    let metadata: UpdateMetadataV2 = serde_json::from_slice(canonical_metadata)
        .map_err(|_| SignedInstalledReleaseVerificationErrorV2::InvalidEncoding)?;
    let canonical = serde_json::to_vec(&metadata)
        .map_err(|_| SignedInstalledReleaseVerificationErrorV2::InvalidEncoding)?;
    if canonical != canonical_metadata {
        return Err(SignedInstalledReleaseVerificationErrorV2::NonCanonicalMetadata);
    }
    Ok(metadata)
}

fn validate_trust(
    trust: &UpdateTrustRootV2,
) -> Result<(), SignedInstalledReleaseVerificationErrorV2> {
    let mut ids = HashSet::new();
    let mut keys = HashSet::new();
    for key in trust
        .root_keys
        .iter()
        .chain([&trust.timestamp_key, &trust.snapshot_key])
    {
        if !valid_key_id(&key.key_id)
            || !ids.insert(key.key_id.as_str())
            || !keys.insert(key.public_key)
            || VerifyingKey::from_bytes(&key.public_key).is_err()
        {
            return Err(SignedInstalledReleaseVerificationErrorV2::InvalidTrustRoot);
        }
    }
    (trust.root_keys.len() == 3)
        .then_some(())
        .ok_or(SignedInstalledReleaseVerificationErrorV2::InvalidTrustRoot)
}

fn valid_key_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn validate_structure(
    metadata: &UpdateMetadataV2,
    trust: &UpdateTrustRootV2,
    now: u64,
) -> Result<(), SignedInstalledReleaseVerificationErrorV2> {
    let root = &metadata.root;
    let target = &metadata.targets.target;
    if metadata.schema_version != SCHEMA_VERSION
        || root.schema_version != SCHEMA_VERSION
        || root.version == 0
        || metadata.targets.version == 0
        || metadata.snapshot.version == 0
        || metadata.timestamp.version == 0
        || root.threshold != ROOT_THRESHOLD as u32
        || root.key_ids
            != trust
                .root_keys
                .iter()
                .map(|key| key.key_id.clone())
                .collect::<Vec<_>>()
        || metadata.snapshot.targets_version != metadata.targets.version
        || metadata.timestamp.snapshot_version != metadata.snapshot.version
    {
        return Err(SignedInstalledReleaseVerificationErrorV2::InvalidMetadata);
    }
    if metadata.targets.expires_at_unix_seconds <= now
        || metadata.snapshot.expires_at_unix_seconds <= now
        || metadata.timestamp.expires_at_unix_seconds <= now
        || target.expires_at_unix_seconds <= now
        || target.published_at_unix_seconds > now
    {
        return Err(SignedInstalledReleaseVerificationErrorV2::Expired);
    }
    Ok(())
}

fn verify_quorum<T: Serialize>(
    signatures: &[UpdateSignatureV2],
    keys: &[UpdateTrustedKeyV2],
    value: &T,
    threshold: usize,
) -> Result<(), ()> {
    if !(threshold..=keys.len()).contains(&signatures.len()) {
        return Err(());
    }
    let bytes = update_metadata_signing_bytes(value).map_err(|_| ())?;
    let mut ids = HashSet::new();
    for signature in signatures {
        if !ids.insert(signature.key_id.as_str()) {
            return Err(());
        }
        let key = keys
            .iter()
            .find(|key| key.key_id == signature.key_id)
            .ok_or(())?;
        verify_bytes(&key.public_key, &bytes, &signature.signature)?;
    }
    Ok(())
}

fn verify_single<T: Serialize>(
    encoded: &str,
    key: &UpdateTrustedKeyV2,
    value: &T,
) -> Result<(), ()> {
    verify_bytes(
        &key.public_key,
        &update_metadata_signing_bytes(value).map_err(|_| ())?,
        encoded,
    )
}

fn verify_bytes(public_key: &[u8; 32], bytes: &[u8], encoded: &str) -> Result<(), ()> {
    if encoded.len() != 128
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(());
    }
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| ())?;
    let decoded = hex::decode(encoded).map_err(|_| ())?;
    let signature = Signature::from_slice(&decoded).map_err(|_| ())?;
    key.verify_strict(bytes, &signature).map_err(|_| ())
}
