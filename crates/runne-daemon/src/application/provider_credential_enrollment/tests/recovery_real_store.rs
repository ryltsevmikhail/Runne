use runne_domain::id::{CommandId, IdempotencyKey};
use runne_provider::{
    AttachCredentialProcess, BeginCredentialOperation, BeginCredentialVerification,
    BindCredentialReadback, ClaimCredentialOperation, CredentialBindingDigest, CredentialFence,
    CredentialLifecycleRevision, CredentialNativeEffectDisposition, CredentialOperationAction,
    CredentialOperationId, CredentialReadbackDisposition, CredentialVerificationKind,
    CredentialVerificationLease, CredentialVerificationResult, CredentialVerifierRevision,
    IssueCredentialTicketDigest, ObserveNativeEffect, ProviderCredentialEnrollmentStore,
    ProviderId,
};
use runne_secure_store::{
    ProviderCredentialVerificationReadback as VerificationReadback, SecureStoreError,
};

use super::super::{
    CredentialEnrollmentReadback as EnrollmentReadback, CredentialEnrollmentRecoveryGateway,
};

struct Reader(CredentialBindingDigest);

impl EnrollmentReadback for Reader {
    fn observe(
        &self,
        operation: &runne_provider::CredentialOperationSnapshot,
        _: &runne_provider::CredentialBrokerCommand,
    ) -> Result<BindCredentialReadback, runne_api::ProviderCredentialEnrollmentHostError> {
        Ok(BindCredentialReadback::new(
            operation.operation_id(),
            CredentialReadbackDisposition::ExactVersion,
            self.0,
        )
        .unwrap())
    }
}

struct VerificationReader(CredentialVerificationResult);

impl VerificationReadback for VerificationReader {
    fn verify_local(
        &self,
        _: &CredentialVerificationLease,
    ) -> Result<CredentialVerificationResult, SecureStoreError> {
        Ok(self.0)
    }
}

fn provider() -> ProviderId {
    ProviderId::new("openai").unwrap()
}
fn op(value: u8) -> CredentialOperationId {
    CredentialOperationId::from_bytes([value; 16]).unwrap()
}
fn digest(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}

fn store_and_claim() -> (
    runne_store::provider::SqliteProviderCredentialLifecycleStore,
    tempfile::TempDir,
    CredentialOperationId,
) {
    let directory = tempfile::tempdir().unwrap();
    let store = runne_store::provider::online_claim_test_support::open_test_store(
        &directory.path().join("recovery.sqlite"),
        100,
    );
    let measurements = runne_store::provider::online_claim_test_support::measurements_for(&store);
    let id = op(41);
    let begin = BeginCredentialOperation::new(
        CommandId::from_bytes([61; 16]),
        IdempotencyKey::new("real-pair").unwrap(),
        id,
        runne_provider::CredentialInstallationOwnerId::from_bytes([7; 32]).unwrap(),
        provider(),
        CredentialOperationAction::Pair,
        Some(runne_provider::CredentialVersionRef::new(provider(), 1).unwrap()),
        None,
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        digest(42),
        4_000_000_000,
    )
    .unwrap()
    .with_qualified_release_tuple(
        measurements
            .issue_qualified_credential_release_tuple(
                measurements.release_manifest_digest([201; 32]).unwrap(),
            )
            .unwrap(),
    );
    ProviderCredentialEnrollmentStore::begin(&store, begin).unwrap();
    ProviderCredentialEnrollmentStore::attach_process(
        &store,
        AttachCredentialProcess::new(id, digest(44)).unwrap(),
    )
    .unwrap();
    let ticket = ProviderCredentialEnrollmentStore::issue_ticket_attempt(
        &store,
        IssueCredentialTicketDigest::new(id, digest(45), digest(44), 100).unwrap(),
    )
    .unwrap();
    let draft =
        ClaimCredentialOperation::new(ticket, digest(45), digest(44), digest(46), 1, 1).unwrap();
    let sealed = runne_store::provider::online_claim_test_support::seal_claim(&store, draft);
    ProviderCredentialEnrollmentStore::claim(&store, sealed).unwrap();
    (store, directory, id)
}

fn run(result: CredentialVerificationResult) {
    let (store, _directory, id) = store_and_claim();
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        &store,
        ObserveNativeEffect::new(id, CredentialNativeEffectDisposition::PossibleEffect),
    )
    .unwrap();
    let verification_reader = VerificationReader(result);
    let reader = Reader(digest(45));
    let gateway =
        CredentialEnrollmentRecoveryGateway::new_with_local(&store, &reader, &verification_reader);
    gateway.reconcile_online(100).unwrap();
    assert_eq!(
        ProviderCredentialEnrollmentStore::load_operation(&store, id)
            .unwrap()
            .state(),
        runne_provider::CredentialOperationState::Completed
    );
    let context =
        ProviderCredentialEnrollmentStore::current_verification_context(&store, &provider())
            .unwrap();
    let remote = BeginCredentialVerification::new(
        op(99),
        Some(id),
        provider(),
        CredentialVerificationKind::Remote,
        context.lifecycle_revision(),
        context.fence(),
        context.readiness_revision(),
        context.release_tuple_digest(),
        digest(46),
        CredentialVerifierRevision::new(1).unwrap(),
        101,
        130,
    )
    .unwrap();
    let remote_result = ProviderCredentialEnrollmentStore::begin_verification(&store, remote);
    match result {
        CredentialVerificationResult::Verified => {
            assert!(
                remote_result.is_ok(),
                "remote verification failed: {remote_result:?}"
            )
        }
        CredentialVerificationResult::Failed => assert!(remote_result.is_err()),
        _ => unreachable!(),
    }
}

#[test]
fn real_store_pair_recovery_records_local_verified_and_allows_remote() {
    run(CredentialVerificationResult::Verified);
}

#[test]
fn real_store_pair_recovery_records_local_failed_and_blocks_remote() {
    run(CredentialVerificationResult::Failed);
}
