use std::fs::File;
use std::io::Read;

use runne_platform_desktop::{
    UpdateMetadataV2, UpdateRootRoleV2, UpdateSignatureV2, UpdateSnapshotRoleV2, UpdateTargetV2,
    UpdateTargetV2Binding, UpdateTargetsRoleV2, UpdateTimestampRoleV2, UpdateTrustRootV2,
    update_metadata_signing_bytes,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::input::UpdateMetadataDraft;
use crate::key_store::{KeySlot, UpdateSigningKeyStore};

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProducerError {
    #[error("update metadata input is invalid")]
    Input,
    #[error("update signing key store is unavailable")]
    KeyStore,
    #[error("update metadata verification failed")]
    Verification,
    #[error("update metadata output failed")]
    Output,
}

pub fn issue_metadata(
    draft: &UpdateMetadataDraft,
    keys: &impl UpdateSigningKeyStore,
) -> Result<UpdateMetadataV2, ProducerError> {
    if draft.schema_version != 1 || !draft.artifact_path.is_absolute() {
        return Err(ProducerError::Input);
    }
    let (artifact_size, artifact_sha256) = artifact_identity(draft)?;
    let trust = UpdateTrustRootV2::from_keys(
        [
            (KeySlot::RootA.key_id(), keys.public_key(KeySlot::RootA)?),
            (KeySlot::RootB.key_id(), keys.public_key(KeySlot::RootB)?),
            (KeySlot::RootC.key_id(), keys.public_key(KeySlot::RootC)?),
        ],
        (
            KeySlot::Timestamp.key_id(),
            keys.public_key(KeySlot::Timestamp)?,
        ),
        (
            KeySlot::Snapshot.key_id(),
            keys.public_key(KeySlot::Snapshot)?,
        ),
    );
    let root = UpdateRootRoleV2::from_trust(&trust, draft.root_version);
    let targets = UpdateTargetsRoleV2 {
        version: draft.targets_version,
        expires_at_unix_seconds: draft.expires_at_unix_seconds,
        target: target(draft, artifact_size, artifact_sha256),
    };
    let snapshot = UpdateSnapshotRoleV2 {
        version: draft.snapshot_version,
        expires_at_unix_seconds: draft.expires_at_unix_seconds,
        targets_version: draft.targets_version,
    };
    let timestamp = UpdateTimestampRoleV2 {
        version: draft.timestamp_version,
        expires_at_unix_seconds: draft.expires_at_unix_seconds,
        snapshot_version: draft.snapshot_version,
    };
    let metadata = UpdateMetadataV2 {
        schema_version: 2,
        root_signatures: root_signatures(keys, &root)?,
        targets_signatures: target_signatures(keys, &targets)?,
        snapshot_signature: signature(keys, KeySlot::Snapshot, &snapshot)?,
        timestamp_signature: signature(keys, KeySlot::Timestamp, &timestamp)?,
        root,
        targets,
        snapshot,
        timestamp,
    };
    self_verify(&metadata, &trust, draft)?;
    Ok(metadata)
}

fn artifact_identity(draft: &UpdateMetadataDraft) -> Result<(u64, String), ProducerError> {
    let mut file = File::open(&draft.artifact_path).map_err(|_| ProducerError::Input)?;
    let metadata = file.metadata().map_err(|_| ProducerError::Input)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 {
        return Err(ProducerError::Input);
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let size = file.read(&mut buffer).map_err(|_| ProducerError::Input)?;
        if size == 0 {
            break;
        }
        digest.update(&buffer[..size]);
    }
    Ok((metadata.len(), hex::encode(digest.finalize())))
}

fn target(draft: &UpdateMetadataDraft, size: u64, digest: String) -> UpdateTargetV2 {
    UpdateTargetV2 {
        product_id: draft.product_id.clone(),
        version: draft.version.clone(),
        platform: draft.platform.clone(),
        arch: draft.arch.clone(),
        artifact_sha256: digest,
        artifact_size: size,
        artifact_url: draft.artifact_url.clone(),
        release_candidate_sha256: draft.release_candidate_sha256.clone(),
        min_os: draft.min_os.clone(),
        profile_id: draft.profile_id.clone(),
        bundle_sha256: draft.bundle_sha256.clone(),
        runtime_version: draft.runtime_version.clone(),
        runtime_digest: draft.runtime_digest.clone(),
        channel: draft.channel.clone(),
        published_at_unix_seconds: draft.published_at_unix_seconds,
        expires_at_unix_seconds: draft.expires_at_unix_seconds,
        rollback_floor: draft.rollback_floor.clone(),
        native_enrollment_tuple: None,
    }
}

fn root_signatures(
    keys: &impl UpdateSigningKeyStore,
    role: &UpdateRootRoleV2,
) -> Result<Vec<UpdateSignatureV2>, ProducerError> {
    [KeySlot::RootA, KeySlot::RootB]
        .into_iter()
        .map(|slot| record(keys, slot, role))
        .collect()
}

fn target_signatures(
    keys: &impl UpdateSigningKeyStore,
    role: &UpdateTargetsRoleV2,
) -> Result<Vec<UpdateSignatureV2>, ProducerError> {
    [KeySlot::RootA, KeySlot::RootB]
        .into_iter()
        .map(|slot| record(keys, slot, role))
        .collect()
}

fn record<T: serde::Serialize>(
    keys: &impl UpdateSigningKeyStore,
    slot: KeySlot,
    role: &T,
) -> Result<UpdateSignatureV2, ProducerError> {
    Ok(UpdateSignatureV2 {
        key_id: slot.key_id().into(),
        signature: signature(keys, slot, role)?,
    })
}

fn signature<T: serde::Serialize>(
    keys: &impl UpdateSigningKeyStore,
    slot: KeySlot,
    role: &T,
) -> Result<String, ProducerError> {
    let bytes = update_metadata_signing_bytes(role).map_err(|_| ProducerError::Input)?;
    Ok(hex::encode(keys.sign(slot, &bytes)?))
}

fn self_verify(
    metadata: &UpdateMetadataV2,
    trust: &UpdateTrustRootV2,
    draft: &UpdateMetadataDraft,
) -> Result<(), ProducerError> {
    let target = &metadata.targets.target;
    let binding = UpdateTargetV2Binding {
        product_id: &target.product_id,
        platform: &target.platform,
        arch: &target.arch,
        min_os: &target.min_os,
        profile_id: &target.profile_id,
        bundle_sha256: &target.bundle_sha256,
        runtime_version: &target.runtime_version,
        runtime_digest: &target.runtime_digest,
        channel: &target.channel,
    };
    #[cfg(not(all(feature = "dev-loopback-updater", debug_assertions)))]
    let verified = runne_platform_desktop::verify_update_v2(
        metadata,
        trust,
        &binding,
        draft.published_at_unix_seconds,
        &draft.current_version,
        &draft.rollback_floor,
    );
    #[cfg(all(feature = "dev-loopback-updater", debug_assertions))]
    let verified = runne_platform_desktop::verify_update_v2_dev_loopback(
        metadata,
        trust,
        &binding,
        draft.published_at_unix_seconds,
        &draft.current_version,
        &draft.rollback_floor,
    );
    verified
        .map(|_| ())
        .map_err(|_| ProducerError::Verification)
}
