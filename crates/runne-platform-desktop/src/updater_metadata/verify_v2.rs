use super::{
    MAX_ARTIFACT_BYTES, ROOT_THRESHOLD, SCHEMA_VERSION, UpdateMetadataV2, UpdateTargetV2Binding,
    UpdateTrustRootV2, UpdateV2VerificationError, VerifiedUpdateV2, root_matches, target_matches,
    verify_quorum, verify_single,
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
    validate_structure(metadata, trust)?;
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
    validate_target(metadata, binding, now, dev_loopback)?;
    let version = crate::updater::parse_version(&metadata.targets.target.version)
        .map_err(|_| UpdateV2VerificationError::InvalidMetadata)?;
    let current = crate::updater::parse_version(current)
        .map_err(|_| UpdateV2VerificationError::InvalidMetadata)?;
    let floor = crate::updater::parse_version(floor)
        .map_err(|_| UpdateV2VerificationError::InvalidMetadata)?;
    let target_floor = crate::updater::parse_version(&metadata.targets.target.rollback_floor)
        .map_err(|_| UpdateV2VerificationError::InvalidMetadata)?;
    if version < current || version < floor || target_floor < floor {
        return Err(UpdateV2VerificationError::Rollback);
    }
    Ok(VerifiedUpdateV2 {
        metadata: metadata.clone(),
        verified_at_unix_seconds: now,
    })
}

fn validate_structure(
    metadata: &UpdateMetadataV2,
    trust: &UpdateTrustRootV2,
) -> Result<(), UpdateV2VerificationError> {
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
    Ok(())
}

fn validate_target(
    metadata: &UpdateMetadataV2,
    binding: &UpdateTargetV2Binding<'_>,
    now: u64,
    dev_loopback: bool,
) -> Result<(), UpdateV2VerificationError> {
    let target = &metadata.targets.target;
    if metadata.targets.expires_at_unix_seconds <= now
        || metadata.snapshot.expires_at_unix_seconds <= now
        || metadata.timestamp.expires_at_unix_seconds <= now
        || target.expires_at_unix_seconds <= now
        || target.published_at_unix_seconds > now
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
        || !crate::updater_feed::is_update_url(&target.artifact_url, dev_loopback)
        || target
            .native_enrollment_tuple
            .as_ref()
            .is_some_and(|tuple| !tuple.matches_target(target))
    {
        return Err(UpdateV2VerificationError::InvalidMetadata);
    }
    let kind = crate::UpdateArtifactKind::from_url(&target.artifact_url)
        .map_err(|_| UpdateV2VerificationError::InvalidMetadata)?;
    kind.supports_platform(&target.platform)
        .then_some(())
        .ok_or(UpdateV2VerificationError::InvalidMetadata)
}
