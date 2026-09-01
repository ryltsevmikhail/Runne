use runne_api::SignedInstalledReleaseVerificationErrorV2 as SignedError;

use super::{
    MAX_ARTIFACT_BYTES, UpdateMetadataV2, UpdateTargetV2Binding, UpdateTrustRootV2,
    UpdateV2VerificationError, VerifiedUpdateV2, target_matches,
};

pub fn verify_update_v2(
    metadata: &UpdateMetadataV2,
    trust: &UpdateTrustRootV2,
    binding: &UpdateTargetV2Binding<'_>,
    now: u64,
    current: &str,
    floor: &str,
) -> Result<VerifiedUpdateV2, UpdateV2VerificationError> {
    verify(metadata, trust, binding, now, current, floor, false)
}

#[cfg(all(feature = "dev-loopback-updater", debug_assertions))]
pub fn verify_update_v2_dev_loopback(
    metadata: &UpdateMetadataV2,
    trust: &UpdateTrustRootV2,
    binding: &UpdateTargetV2Binding<'_>,
    now: u64,
    current: &str,
    floor: &str,
) -> Result<VerifiedUpdateV2, UpdateV2VerificationError> {
    verify(metadata, trust, binding, now, current, floor, true)
}

#[allow(clippy::too_many_arguments)]
fn verify(
    metadata: &UpdateMetadataV2,
    trust: &UpdateTrustRootV2,
    binding: &UpdateTargetV2Binding<'_>,
    now: u64,
    current: &str,
    floor: &str,
    dev_loopback: bool,
) -> Result<VerifiedUpdateV2, UpdateV2VerificationError> {
    let signed = runne_api::verify_signed_update_metadata_v2(metadata, trust, now)
        .map_err(map_signed_error)?;
    validate_target(signed.target(), binding, dev_loopback)?;
    let version = crate::updater::parse_version(&signed.target().version)
        .map_err(|_| UpdateV2VerificationError::InvalidMetadata)?;
    let current = crate::updater::parse_version(current)
        .map_err(|_| UpdateV2VerificationError::InvalidMetadata)?;
    let floor = crate::updater::parse_version(floor)
        .map_err(|_| UpdateV2VerificationError::InvalidMetadata)?;
    let target_floor = crate::updater::parse_version(&signed.target().rollback_floor)
        .map_err(|_| UpdateV2VerificationError::InvalidMetadata)?;
    if version < current || version < floor || target_floor < floor {
        return Err(UpdateV2VerificationError::Rollback);
    }
    Ok(VerifiedUpdateV2 { signed })
}

const fn map_signed_error(error: SignedError) -> UpdateV2VerificationError {
    match error {
        SignedError::RootQuorum => UpdateV2VerificationError::RootQuorum,
        SignedError::TargetsQuorum => UpdateV2VerificationError::TargetsQuorum,
        SignedError::SnapshotSignature => UpdateV2VerificationError::SnapshotSignature,
        SignedError::TimestampSignature => UpdateV2VerificationError::TimestampSignature,
        SignedError::Expired => UpdateV2VerificationError::Expired,
        SignedError::MetadataTooLarge
        | SignedError::InvalidEncoding
        | SignedError::NonCanonicalMetadata
        | SignedError::InvalidTrustRoot
        | SignedError::InvalidMetadata
        | SignedError::Unqualified
        | SignedError::ReleaseBindingMismatch => UpdateV2VerificationError::InvalidMetadata,
    }
}

fn validate_target(
    target: &super::UpdateTargetV2,
    binding: &UpdateTargetV2Binding<'_>,
    dev_loopback: bool,
) -> Result<(), UpdateV2VerificationError> {
    if !target_matches(target, binding) {
        return Err(UpdateV2VerificationError::TargetMismatch);
    }
    if target.artifact_size == 0
        || target.artifact_size > MAX_ARTIFACT_BYTES
        || !crate::updater::is_sha256(&target.artifact_sha256)
        || !crate::updater::is_sha256(&target.bundle_sha256)
        || !crate::updater::is_sha256(&target.runtime_digest)
        || !crate::updater_feed::is_update_url(&target.artifact_url, dev_loopback)
    {
        return Err(UpdateV2VerificationError::InvalidMetadata);
    }
    let kind = crate::UpdateArtifactKind::from_url(&target.artifact_url)
        .map_err(|_| UpdateV2VerificationError::InvalidMetadata)?;
    kind.supports_platform(&target.platform)
        .then_some(())
        .ok_or(UpdateV2VerificationError::InvalidMetadata)
}
