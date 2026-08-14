#[cfg(any(test, feature = "fixture-only"))]
#[derive(Clone)]
pub struct ThresholdMetadataParts {
    pub candidate: crate::Digest,
    pub inventory: crate::Digest,
    pub versions: std::collections::BTreeMap<String, u64>,
    pub rollback_floor: u64,
    pub expires_at: u64,
    pub revocation_epoch: u64,
    pub frozen: bool,
    pub root_keyset: Vec<(String, [u8; 32])>,
    pub targets_keyset: Vec<(String, [u8; 32])>,
    pub snapshot_key_id: String,
    pub timestamp_key_id: String,
    pub channel_selector: String,
    pub root_predecessor_body: crate::Digest,
    pub root_predecessor_keyset: crate::Digest,
    pub root_body: Vec<u8>,
    pub targets_body: Vec<u8>,
    pub snapshot_body: Vec<u8>,
    pub timestamp_body: Vec<u8>,
    pub root_successor: Vec<(String, [u8; 64])>,
    pub root_self: Vec<(String, [u8; 64])>,
    pub targets_root: Vec<(String, [u8; 64])>,
    pub targets_self: Vec<(String, [u8; 64])>,
    pub snapshot_signature: (String, [u8; 64]),
    pub timestamp_signature: (String, [u8; 64]),
    pub targets: [ThresholdTargetParts; 3],
}
#[derive(Clone)]
pub struct ThresholdTargetParts {
    pub slot: String,
    pub app_version: String,
    pub release_sequence: u64,
    pub bundle_id: String,
    pub platform: String,
    pub architecture: String,
    pub artifact: crate::Digest,
    pub length: u64,
    pub minimum_os: (String, crate::Digest),
    pub profiles: Vec<(String, crate::Digest)>,
    pub runtime: (String, crate::Digest),
}

pub fn targets(
    value: Vec<super::super::rc2_threshold::UpdateTarget>,
) -> Option<[ThresholdTargetParts; 3]> {
    let targets: [super::super::rc2_threshold::UpdateTarget; 3] = value.try_into().ok()?;
    Some(targets.map(|target| {
        ThresholdTargetParts {
            slot: target.slot,
            app_version: target.app_version,
            release_sequence: target.release_sequence,
            bundle_id: target.bundle_id,
            platform: target.platform,
            architecture: target.architecture,
            artifact: target.artifact_sha256.0,
            length: target.artifact_length,
            minimum_os: (target.min_os_policy_id, target.min_os_policy_sha256.0),
            profiles: target
                .profiles
                .into_iter()
                .map(|profile| (profile.profile_id, profile.bundle_sha256.0))
                .collect(),
            runtime: (target.runtime_version, target.runtime_sha256.0),
        }
    }))
}
