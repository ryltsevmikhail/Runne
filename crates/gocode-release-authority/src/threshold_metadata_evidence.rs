use crate::threshold_context::ThresholdMetadataEvidence;
use crate::wire::semantics::ThresholdMetadataParts;

pub fn from_parts(parts: ThresholdMetadataParts) -> ThresholdMetadataEvidence {
    ThresholdMetadataEvidence {
        root_keyset: parts.root_keyset,
        targets_keyset: parts.targets_keyset,
        snapshot_key: parts.snapshot_key_id,
        timestamp_key: parts.timestamp_key_id,
        channel_selector: parts.channel_selector,
        root_predecessor_body: parts.root_predecessor_body,
        root_predecessor_keyset: parts.root_predecessor_keyset,
        root_body: parts.root_body,
        targets_body: parts.targets_body,
        snapshot_body: parts.snapshot_body,
        timestamp_body: parts.timestamp_body,
        root_successor: parts.root_successor,
        root_self: parts.root_self,
        targets_root: parts.targets_root,
        targets_self: parts.targets_self,
        snapshot_signature: parts.snapshot_signature,
        timestamp_signature: parts.timestamp_signature,
        expires_at: parts.expires_at,
        revocation_epoch: parts.revocation_epoch,
        frozen: parts.frozen,
        next_versions: parts.versions,
        rollback_floor: parts.rollback_floor,
    }
}
