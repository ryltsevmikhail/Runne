//! Shared harness for the T1 admission integration tests.
use std::sync::Mutex;

use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use runne_application::project_trust::{
    PermissionMode, ProjectTrustPersistence, ProjectTrustProjectId, ProjectTrustRecord,
    ProjectTrustStatus, SourceAdmissionRequest, SourceChannel, TrustPersistenceError, TrustToken,
};

pub(super) const EPOCH: u64 = 0x5a5a_5a5a_5a5a_5a5a;

pub(super) struct FakePersistence {
    record: Mutex<ProjectTrustRecord>,
    fail: bool,
}

impl FakePersistence {
    pub(super) fn with(record: ProjectTrustRecord) -> Self {
        Self {
            record: Mutex::new(record),
            fail: false,
        }
    }

    pub(super) fn failing() -> Self {
        Self {
            record: Mutex::new(ProjectTrustRecord::untrusted_default(EPOCH)),
            fail: true,
        }
    }
}

impl ProjectTrustPersistence for FakePersistence {
    fn has_explicit_record(&self, _: ProjectTrustProjectId) -> Result<bool, TrustPersistenceError> {
        Ok(true)
    }

    fn load(&self, _: ProjectTrustProjectId) -> Result<ProjectTrustRecord, TrustPersistenceError> {
        if self.fail {
            return Err(TrustPersistenceError::Unavailable);
        }
        Ok(*self.record.lock().unwrap())
    }

    fn instance_epoch(&self) -> Result<u64, TrustPersistenceError> {
        if self.fail {
            return Err(TrustPersistenceError::Unavailable);
        }
        Ok(self.record.lock().unwrap().instance_epoch)
    }

    fn commit(
        &self,
        _: ProjectTrustProjectId,
        status: ProjectTrustStatus,
        mask: u32,
        expected: TrustToken,
    ) -> Result<ProjectTrustRecord, TrustPersistenceError> {
        let mut record = self.record.lock().unwrap();
        if expected.instance_epoch != record.instance_epoch {
            return Err(TrustPersistenceError::ForeignEpoch {
                expected_epoch: expected.instance_epoch,
                current_epoch: record.instance_epoch,
            });
        }
        if expected.revision != record.revision {
            return Err(TrustPersistenceError::Conflict {
                expected: expected.revision,
                current: record.revision,
            });
        }
        record.status = status;
        record.managed_deny_mask = mask;
        record.revision += 1;
        Ok(*record)
    }
}

pub(super) struct UnavailableInspection;

impl ProhibitedContentPort for UnavailableInspection {
    fn inspect(
        &self,
        _: CanonicalContentBoundary,
        _: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Err(ContentGuardError::Unavailable)
    }
}

pub(super) struct WorkingInspection {
    pub(super) calls: Mutex<u32>,
}

impl WorkingInspection {
    pub(super) fn new() -> Self {
        Self {
            calls: Mutex::new(0),
        }
    }
}

impl ProhibitedContentPort for WorkingInspection {
    fn inspect(
        &self,
        boundary: CanonicalContentBoundary,
        bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        *self.calls.lock().unwrap() += 1;
        let _ = boundary;
        Ok(if bytes.is_empty() {
            ContentDisposition::Allowed { policy_epoch: 9 }
        } else {
            ContentDisposition::Prohibited { policy_epoch: 9 }
        })
    }
}

pub(super) fn project() -> ProjectTrustProjectId {
    ProjectTrustProjectId::from_bytes([7; 16])
}

pub(super) fn request(channel: SourceChannel, path: Option<&str>) -> SourceAdmissionRequest<'_> {
    SourceAdmissionRequest {
        channel,
        path,
        observed_token: None,
        permission_mode: PermissionMode::Ask,
    }
}

pub(super) fn trusted(record_revision: u64) -> ProjectTrustRecord {
    ProjectTrustRecord {
        status: ProjectTrustStatus::Trusted,
        instance_epoch: EPOCH,
        revision: record_revision,
        managed_deny_mask: 0,
    }
}
