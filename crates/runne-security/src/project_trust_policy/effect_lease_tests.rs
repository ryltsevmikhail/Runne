use super::*;
use runne_application::project_trust::{
    PermissionMode, ProjectTrustEffectLease, ProjectTrustPersistence, TrustPersistenceError,
};
use std::sync::Mutex;

struct FakeLease(ProjectTrustRecord);
impl ProjectTrustEffectLease for FakeLease {
    fn record(&self) -> ProjectTrustRecord {
        self.0
    }
}

struct FakePersistence(Mutex<ProjectTrustRecord>);
impl ProjectTrustPersistence for FakePersistence {
    fn load(
        &self,
        _project: ProjectTrustProjectId,
    ) -> Result<ProjectTrustRecord, TrustPersistenceError> {
        Ok(*self.0.lock().unwrap())
    }

    fn has_explicit_record(
        &self,
        _project: ProjectTrustProjectId,
    ) -> Result<bool, TrustPersistenceError> {
        Ok(self.0.lock().unwrap().revision != 0)
    }

    fn instance_epoch(&self) -> Result<u64, TrustPersistenceError> {
        Ok(self.0.lock().unwrap().instance_epoch)
    }

    fn acquire_effect_lease(
        &self,
        _project: ProjectTrustProjectId,
    ) -> Result<Box<dyn ProjectTrustEffectLease>, TrustPersistenceError> {
        Ok(Box::new(FakeLease(*self.0.lock().unwrap())))
    }

    fn commit(
        &self,
        _project: ProjectTrustProjectId,
        _status: ProjectTrustStatus,
        _managed_deny_mask: u32,
        _expected: runne_application::project_trust::TrustToken,
    ) -> Result<ProjectTrustRecord, TrustPersistenceError> {
        Err(TrustPersistenceError::Unavailable)
    }
}

struct LegacyPersistence(ProjectTrustRecord);
impl ProjectTrustPersistence for LegacyPersistence {
    fn load(
        &self,
        _project: ProjectTrustProjectId,
    ) -> Result<ProjectTrustRecord, TrustPersistenceError> {
        Ok(self.0)
    }

    fn has_explicit_record(
        &self,
        _project: ProjectTrustProjectId,
    ) -> Result<bool, TrustPersistenceError> {
        Ok(self.0.revision != 0)
    }

    fn instance_epoch(&self) -> Result<u64, TrustPersistenceError> {
        Ok(self.0.instance_epoch)
    }

    fn commit(
        &self,
        _project: ProjectTrustProjectId,
        _status: ProjectTrustStatus,
        _managed_deny_mask: u32,
        _expected: runne_application::project_trust::TrustToken,
    ) -> Result<ProjectTrustRecord, TrustPersistenceError> {
        Err(TrustPersistenceError::Unavailable)
    }
}

fn request(permission_mode: PermissionMode) -> SourceAdmissionRequest<'static> {
    SourceAdmissionRequest {
        channel: SourceChannel::FilesList,
        path: None,
        observed_token: None,
        permission_mode,
    }
}

#[test]
fn effect_lease_reuses_policy_and_denies_revoked_current_record() {
    let project = ProjectTrustProjectId::from_bytes([0x31; 16]);
    let revoked = ProjectTrustRecord {
        status: ProjectTrustStatus::Untrusted,
        instance_epoch: 3,
        revision: 2,
        managed_deny_mask: 0,
    };
    let authority =
        ProjectTrustPolicyAuthority::new(Arc::new(FakePersistence(Mutex::new(revoked))));
    let result = authority.acquire_effect_lease(project, request(PermissionMode::Ask));
    assert!(matches!(
        result,
        Err(TrustAdmissionError::DeniedByPolicy {
            reason: SourceDenyReason::Untrusted
        })
    ));
}

#[test]
fn effect_lease_default_fails_closed_for_unsupported_persistence() {
    let project = ProjectTrustProjectId::from_bytes([0x32; 16]);
    let trusted = ProjectTrustRecord {
        status: ProjectTrustStatus::Trusted,
        instance_epoch: 3,
        revision: 1,
        managed_deny_mask: 0,
    };
    let authority = ProjectTrustPolicyAuthority::new(Arc::new(LegacyPersistence(trusted)));
    assert!(matches!(
        authority.acquire_effect_lease(project, request(PermissionMode::Ask)),
        Err(TrustAdmissionError::AuthorityUnavailable)
    ));
}

#[test]
fn effect_lease_rejects_absent_default_record() {
    let project = ProjectTrustProjectId::from_bytes([0x33; 16]);
    let absent = ProjectTrustRecord::untrusted_default(3);
    let authority = ProjectTrustPolicyAuthority::new(Arc::new(FakePersistence(Mutex::new(absent))));
    assert!(matches!(
        authority.acquire_effect_lease(project, request(PermissionMode::FullAccess)),
        Err(TrustAdmissionError::DeniedByPolicy {
            reason: SourceDenyReason::Untrusted
        })
    ));
}

#[test]
fn effect_lease_preserves_managed_deny_under_full_access_mode() {
    let project = ProjectTrustProjectId::from_bytes([0x34; 16]);
    let managed_deny = ProjectTrustRecord {
        status: ProjectTrustStatus::Managed,
        instance_epoch: 3,
        revision: 4,
        managed_deny_mask: SourceChannel::FilesList.mask_bit(),
    };
    let authority =
        ProjectTrustPolicyAuthority::new(Arc::new(FakePersistence(Mutex::new(managed_deny))));
    assert!(matches!(
        authority.acquire_effect_lease(project, request(PermissionMode::FullAccess)),
        Err(TrustAdmissionError::DeniedByPolicy {
            reason: SourceDenyReason::ManagedDeny
        })
    ));
}
