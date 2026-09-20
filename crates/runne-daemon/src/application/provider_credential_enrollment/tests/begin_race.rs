use std::sync::{Arc, Barrier};

use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialBeginIntentBinding,
    ProviderCredentialEnrollmentActionV2, ProviderCredentialEnrollmentHostError,
    ProviderCredentialProviderV2, ProviderCredentialRequestAuthorityPair,
};
use runne_provider::{
    CredentialAuthorityPair, CredentialEnrollmentAuthorityPair, CredentialOperationSnapshot,
};

use super::super::{CredentialEnrollmentReadback, ProviderCredentialAdmission};
use super::begin_admission_support::context;

struct NoReadback;

impl CredentialEnrollmentReadback for NoReadback {
    fn observe(
        &self,
        _: &CredentialOperationSnapshot,
        _: &runne_provider::CredentialBrokerCommand,
    ) -> Result<runne_provider::BindCredentialReadback, ProviderCredentialEnrollmentHostError> {
        Err(ProviderCredentialEnrollmentHostError::InvariantViolation)
    }
}

#[test]
fn two_identical_begins_share_one_reserved_effect_and_exact_projection() {
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let command = BeginProviderCredentialEnrollment::new(
        ProviderCredentialEnrollmentActionV2::Pair,
        ProviderCredentialProviderV2::OpenAi,
        1,
        "018f8d23-7f90-7c00-8000-000000000001",
        "race-idempotency",
        "race-intent",
    )
    .unwrap();
    let context = context();
    let intent = ProviderCredentialBeginIntentBinding::new(&command, &context);
    let proof = issuer
        .issue_intent_proof(
            [6; 32],
            [3; 32],
            *intent.action_provider_revision_digest(),
            *intent.command_identity_digest(),
            4_000_000_000,
        )
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let (lifecycle_authority, _) = CredentialAuthorityPair::new().split();
    let (enrollment_authority, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let store =
        runne_store::provider::SqliteProviderCredentialLifecycleStore::open_with_authorities(
            &{
                let daemon = directory.path().join("runne-daemon");
                std::fs::create_dir_all(&daemon).unwrap();
                daemon.join("begin-race.sqlite")
            },
            lifecycle_authority,
            enrollment_authority,
        )
        .unwrap();
    let handles =
        super::super::operation_handle::ProviderCredentialOperationHandleIssuer::new([9; 32]);
    let rendezvous =
        super::super::broker::pending::PendingBrokerRendezvousRegistry::new(handles.duplicate());
    rendezvous.reserve_new_for_test(&authority, &proof);
    let barrier = Arc::new(Barrier::new(2));
    let reader = NoReadback;

    let results = std::thread::scope(|scope| {
        let run = |verifier, measurements, barrier| {
            super::super::begin::ProviderCredentialEnrollmentBegin::new(
                ProviderCredentialAdmission::new(verifier, measurements),
                handles.duplicate(),
                &store,
                &reader,
                rendezvous.clone(),
            )
            .with_before_gate_barrier(barrier)
            .admit(&authority, &proof, &context, &command, 100)
        };
        let left = scope.spawn({
            let verifier = verifier.clone();
            let measurements = measurements.clone();
            let barrier = Arc::clone(&barrier);
            move || run(verifier, measurements, barrier)
        });
        let right = scope.spawn({
            let barrier = Arc::clone(&barrier);
            move || run(verifier, measurements, barrier)
        });
        (
            left.join().unwrap().unwrap(),
            right.join().unwrap().unwrap(),
        )
    });

    assert_eq!(results.0.operation_handle(), results.1.operation_handle());
    assert_eq!(
        results.0.broker_rendezvous_id(),
        results.1.broker_rendezvous_id()
    );
    let operation_id = handles.resolve(results.0.operation_handle()).unwrap();
    assert!(rendezvous.has_live(operation_id, 100));
}
