//! Canonical digest for the currently authoritative T1 managed snapshot.

use runne_domain::id::IntegrityDigest;
use sha2::{Digest, Sha256};

use crate::project_trust::{ProjectTrustProjectId, ProjectTrustRecord, ProjectTrustStatus};

/// Hash the exact T1 policy record that must remain stable across D21 command
/// issuance, proof verification, and the Store's fenced mode-change commit.
pub fn managed_policy_semantics_digest(
    project_id: ProjectTrustProjectId,
    record: ProjectTrustRecord,
) -> IntegrityDigest {
    let mut hash = Sha256::new();
    hash.update(b"runne:d21:managed-policy-snapshot:v1\0");
    hash.update(project_id.as_bytes());
    hash.update(record.instance_epoch.to_be_bytes());
    hash.update(record.revision.to_be_bytes());
    hash.update([match record.status {
        ProjectTrustStatus::Untrusted => 1,
        ProjectTrustStatus::Trusted => 2,
        ProjectTrustStatus::Managed => 3,
    }]);
    hash.update(record.managed_deny_mask.to_be_bytes());
    IntegrityDigest::from_bytes(hash.finalize().into())
}
