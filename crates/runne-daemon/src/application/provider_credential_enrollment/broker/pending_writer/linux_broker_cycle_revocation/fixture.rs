use super::*;
use crate::application::provider_credential_enrollment::broker::ProviderCredentialBroker;
use runne_domain::id::{CommandId, IdempotencyKey};

pub(super) struct DurableFixture {
    _directory: tempfile::TempDir,
    pub(super) path: std::path::PathBuf,
    pub(super) lifecycle: CredentialLifecycleAuthority,
    pub(super) enrollment: CredentialEnrollmentStoreAuthority,
    pub(super) measurements: std::sync::Arc<CredentialEnrollmentMeasurementAuthority>,
    pub(super) store: Option<runne_store::provider::SqliteProviderCredentialLifecycleStore>,
    pub(super) broker: ProviderCredentialBroker,
    pub(super) operation: CredentialOperationSnapshot,
    pub(super) continuation: CredentialBindingDigest,
}

impl DurableFixture {
    pub(super) fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("daemon").join("lifecycle.sqlite");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let (lifecycle, _) = CredentialAuthorityPair::new().split();
        let (enrollment, measurements) = CredentialEnrollmentAuthorityPair::new().split();
        let measurements = std::sync::Arc::new(measurements);
        let store =
            runne_store::provider::SqliteProviderCredentialLifecycleStore::open_with_authorities(
                &path,
                lifecycle.clone(),
                enrollment.clone(),
            )
            .unwrap();
        let provider = ProviderId::new("openai").unwrap();
        store.begin_admission_snapshot(&provider).unwrap();
        let version = disposable_version();
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE provider_credential_authority_heads SET next_credential_version=?1 WHERE provider_id=?2",
                rusqlite::params![i64::try_from(version).unwrap(), provider.as_str()],
            )
            .unwrap();
        let qualified = measurements
            .issue_qualified_credential_release_tuple(
                measurements.release_manifest_digest([9; 32]).unwrap(),
            )
            .unwrap();
        let expires = unix_now() + 600;
        let operation = store
            .begin(
                BeginCredentialOperation::new(
                    CommandId::from_bytes([1; 16]),
                    IdempotencyKey::new("linux-pair-seed").unwrap(),
                    CredentialOperationId::from_bytes([2; 16]).unwrap(),
                    owner(),
                    provider.clone(),
                    CredentialOperationAction::Pair,
                    Some(CredentialVersionRef::new(provider, version).unwrap()),
                    None,
                    CredentialLifecycleRevision::new(1).unwrap(),
                    CredentialFence::new(1).unwrap(),
                    digest(4),
                    expires as u64,
                )
                .unwrap()
                .with_qualified_release_tuple(qualified),
            )
            .unwrap();
        let operation = match operation {
            BeginCredentialOperationOutcome::FreshWinner(operation) => operation,
            BeginCredentialOperationOutcome::ExactReplay(_) => unreachable!(),
        };
        Self {
            _directory: directory,
            path,
            lifecycle,
            enrollment,
            broker: ProviderCredentialBroker::new(measurements.clone()),
            measurements,
            store: Some(store),
            operation,
            continuation: digest(5),
        }
    }

    pub(super) fn store(&self) -> &runne_store::provider::SqliteProviderCredentialLifecycleStore {
        self.store.as_ref().unwrap()
    }
    pub(super) fn close_store(&mut self) {
        drop(self.store.take());
    }
    pub(super) fn reopen_store(&mut self) {
        self.store = Some(
            runne_store::provider::SqliteProviderCredentialLifecycleStore::open_with_authorities(
                &self.path,
                self.lifecycle.clone(),
                self.enrollment.clone(),
            )
            .unwrap(),
        );
    }

    pub(super) fn begin_revoke(
        &mut self,
        target: CredentialVersionRef,
    ) -> CredentialOperationSnapshot {
        let head = self.store().lifecycle_snapshot(target.provider()).unwrap();
        let tuple = self
            .measurements
            .issue_qualified_credential_release_tuple(
                self.measurements.release_manifest_digest([9; 32]).unwrap(),
            )
            .unwrap();
        let now = unix_now();
        let operation = self
            .store()
            .begin(
                BeginCredentialOperation::new(
                    CommandId::from_bytes([6; 16]),
                    IdempotencyKey::new("linux-revoke-seed").unwrap(),
                    CredentialOperationId::from_bytes([7; 16]).unwrap(),
                    owner(),
                    target.provider().clone(),
                    CredentialOperationAction::Revoke,
                    None,
                    Some(target),
                    head.lifecycle_revision(),
                    head.fence(),
                    digest(8),
                    (now + 600) as u64,
                )
                .unwrap()
                .with_qualified_release_tuple(tuple),
            )
            .unwrap();
        let operation = match operation {
            BeginCredentialOperationOutcome::FreshWinner(operation) => operation,
            BeginCredentialOperationOutcome::ExactReplay(_) => unreachable!(),
        };
        self.operation = operation.clone();
        self.continuation = digest(45);
        operation
    }

    pub(super) fn stale_pair_begin(
        &self,
    ) -> Result<BeginCredentialOperationOutcome, CredentialLifecycleError> {
        let next_version = self
            .store()
            .lifecycle_snapshot(self.operation.provider())
            .unwrap()
            .next_credential_version();
        let target =
            CredentialVersionRef::new(self.operation.provider().clone(), next_version).unwrap();
        let tuple = self
            .measurements
            .issue_qualified_credential_release_tuple(
                self.measurements.release_manifest_digest([9; 32]).unwrap(),
            )
            .unwrap();
        self.store().begin(
            BeginCredentialOperation::new(
                CommandId::from_bytes([16; 16]),
                IdempotencyKey::new("stale-pair-after-revoke").unwrap(),
                CredentialOperationId::from_bytes([17; 16]).unwrap(),
                owner(),
                self.operation.provider().clone(),
                CredentialOperationAction::Pair,
                Some(target),
                None,
                CredentialLifecycleRevision::new(2).unwrap(),
                CredentialFence::new(2).unwrap(),
                digest(18),
                (unix_now() + 600) as u64,
            )
            .unwrap()
            .with_qualified_release_tuple(tuple),
        )
    }
}

pub(super) fn owner() -> CredentialInstallationOwnerId {
    CredentialInstallationOwnerId::from_bytes([3; 32]).unwrap()
}
pub(super) fn digest(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}
pub(super) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn disposable_version() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}
