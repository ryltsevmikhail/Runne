use runne_application::project_trust::{
    ProjectTrustEffectLease, ProjectTrustEffectPolicySnapshot, ProjectTrustProjectId,
    ProjectTrustRecord, ProjectTrustStatus,
};
use runne_domain::id::IntegrityDigest;

use crate::store::permission_modes::{
    PermissionModeAuthorityContext,
    identity::OwnedWorkspace,
    managed_identity,
    model::{ManagedSnapshot, PermissionModeStoreError},
};

#[test]
fn snapshot_record_mismatch_fails_closed() {
    let principal = runne_api::ApiPrincipalId::new("lease-mismatch").unwrap();
    let project = ProjectTrustProjectId::from_bytes([0x21; 16]);
    let lease_record = record(2);
    let snapshot = ProjectTrustEffectPolicySnapshot {
        record: record(3),
        policy: runne_application::project_trust::ManagedEffectPolicyV1::all_allow(),
    };
    let lease = MismatchLease {
        record: lease_record,
        snapshot,
    };
    let authority = PermissionModeAuthorityContext::new(&principal, project, &lease, None);
    let workspace = OwnedWorkspace {
        project_id: *project.as_bytes(),
        project_version: 1,
        workspace_version: 1,
    };
    let managed = managed(lease_record, project);
    assert!(matches!(
        managed_identity::lease::current(&authority, workspace, managed),
        Err(PermissionModeStoreError::ManagedPolicyStale)
    ));
}

struct MismatchLease {
    record: ProjectTrustRecord,
    snapshot: ProjectTrustEffectPolicySnapshot,
}

impl ProjectTrustEffectLease for MismatchLease {
    fn record(&self) -> ProjectTrustRecord {
        self.record
    }

    fn snapshot(
        &self,
    ) -> Result<
        ProjectTrustEffectPolicySnapshot,
        runne_application::project_trust::TrustPersistenceError,
    > {
        Ok(self.snapshot)
    }
}

fn record(revision: u64) -> ProjectTrustRecord {
    ProjectTrustRecord {
        status: ProjectTrustStatus::Managed,
        instance_epoch: 9,
        revision,
        managed_deny_mask: 0,
    }
}

fn managed(record: ProjectTrustRecord, project: ProjectTrustProjectId) -> ManagedSnapshot {
    ManagedSnapshot {
        project_id: project,
        instance_epoch: record.instance_epoch,
        revision: record.revision,
        status: record.status,
        deny_mask: record.managed_deny_mask,
        digest: IntegrityDigest::from_bytes([0x44; 32]),
    }
}
