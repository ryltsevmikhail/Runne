use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialBeginIntentBinding,
    ProviderCredentialEnrollmentActionV2, ProviderCredentialEnrollmentHostError,
    ProviderCredentialOperationKindV2, ProviderCredentialOperationStateV2,
    ProviderCredentialProviderV2, ProviderCredentialRequestAuthorityPair,
};
use runne_provider::{
    CredentialAuthorityPair, CredentialEnrollmentAuthorityPair, CredentialOperationId,
    CredentialOperationSnapshot, ProviderCredentialEnrollmentStore,
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
fn begin_recovers_then_returns_the_exact_idempotent_prepared_projection() {
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let command = BeginProviderCredentialEnrollment::new(
        ProviderCredentialEnrollmentActionV2::Pair,
        ProviderCredentialProviderV2::OpenAi,
        1,
        "018f8d23-7f90-7c00-8000-000000000001",
        "begin-idempotency",
        "begin-intent",
    )
    .unwrap();
    let context = context();
    let binding = ProviderCredentialBeginIntentBinding::new(&command, &context);
    let proof = issuer
        .issue_intent_proof(
            [6; 32],
            [3; 32],
            *binding.action_provider_revision_digest(),
            *binding.command_identity_digest(),
            4_000_000_000,
        )
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let (lifecycle_authority, _) = CredentialAuthorityPair::new().split();
    let (enrollment_authority, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let store =
        runne_store::provider::SqliteProviderCredentialLifecycleStore::open_with_authorities(
            &directory.path().join("begin.sqlite"),
            lifecycle_authority,
            enrollment_authority,
        )
        .unwrap();
    let reader = NoReadback;
    let handles =
        super::super::operation_handle::ProviderCredentialOperationHandleIssuer::new([9; 32]);
    let rendezvous =
        super::super::broker::pending::PendingBrokerRendezvousRegistry::new(handles.duplicate());
    let absent = super::super::begin::ProviderCredentialEnrollmentBegin::new(
        ProviderCredentialAdmission::new(verifier.clone(), measurements.clone()),
        handles.duplicate(),
        &store,
        &reader,
        super::super::broker::pending::PendingBrokerRendezvousRegistry::new(handles.duplicate()),
    );
    assert!(matches!(
        absent.admit(&authority, &proof, &context, &command, 100),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    ));
    let proof_digest =
        runne_provider::CredentialBindingDigest::from_measured(*proof.proof_digest()).unwrap();
    assert!(store.find_by_begin_proof(proof_digest).unwrap().is_none());
    let transition_rendezvous =
        super::super::broker::rendezvous::DaemonOwnedUnixBrokerRendezvous::create().unwrap();
    let transition_facts = (
        transition_rendezvous.channel_binding(),
        transition_rendezvous.publication_public_key(),
    );
    rendezvous
        .reserve_transition_rendezvous(transition_rendezvous, &authority, &proof)
        .unwrap();
    let foreign_session = issuer
        .issue_base([1; 32], [2; 32], [7; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let foreign_session_proof = issuer
        .issue_intent_proof(
            [6; 32],
            [7; 32],
            *binding.action_provider_revision_digest(),
            *binding.command_identity_digest(),
            4_000_000_000,
        )
        .unwrap();
    let foreign_release = issuer
        .issue_base([1; 32], [8; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    for (candidate, candidate_proof) in [
        (&foreign_session, &foreign_session_proof),
        (&foreign_release, &proof),
    ] {
        assert!(matches!(
            rendezvous
                .begin_gate(100)
                .unwrap()
                .preflight(candidate, candidate_proof),
            Err(ProviderCredentialEnrollmentHostError::AccessDenied)
        ));
    }
    let begin = super::super::begin::ProviderCredentialEnrollmentBegin::new(
        ProviderCredentialAdmission::new(verifier, measurements),
        handles.duplicate(),
        &store,
        &reader,
        rendezvous.clone(),
    );

    assert!(
        begin
            .admit(&foreign_session, &proof, &context, &command, 100)
            .is_err()
    );
    assert!(store.find_by_begin_proof(proof_digest).unwrap().is_none());

    let first = begin
        .admit(&authority, &proof, &context, &command, 100)
        .unwrap();
    let replay = begin
        .admit(&authority, &proof, &context, &command, 100)
        .unwrap();

    assert_eq!(first.operation_handle(), replay.operation_handle());
    assert_eq!(
        first.operation_kind(),
        ProviderCredentialOperationKindV2::Pair
    );
    assert_eq!(first.state(), ProviderCredentialOperationStateV2::Prepared);
    assert_eq!(first.lifecycle_revision(), 1);
    assert_eq!(first.readiness_revision(), 1);
    let operation_handle = hex::encode(first.operation_handle().as_bytes());
    assert_ne!(
        first.broker_rendezvous_id(),
        Some(operation_handle.as_str())
    );
    let operation = store
        .load_operation(handles.resolve(first.operation_handle()).unwrap())
        .unwrap();
    assert!(rendezvous.has_live(operation.operation_id(), 100));
    let handoff = rendezvous
        .begin_endpoint_handoff(
            first.broker_rendezvous_id().unwrap(),
            &operation,
            &authority,
            &proof,
            100,
        )
        .unwrap();
    assert_eq!(handoff.rendezvous_facts(), transition_facts);
    assert!(!rendezvous.has_live(operation.operation_id(), 100));
    let consumed_replay = begin
        .admit(&authority, &proof, &context, &command, 100)
        .unwrap();
    assert_eq!(consumed_replay.operation_handle(), first.operation_handle());
    assert_eq!(consumed_replay.broker_rendezvous_id(), None);
    assert!(matches!(
        rendezvous.begin_endpoint_handoff(
            first.broker_rendezvous_id().unwrap(),
            &operation,
            &authority,
            &proof,
            100,
        ),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    ));

    let duplicate =
        super::super::broker::pending::PendingBrokerRendezvousRegistry::new(handles.duplicate());
    duplicate.reserve_new_for_test(&authority, &proof);
    assert!(matches!(
        duplicate.begin_endpoint_handoff(
            first.broker_rendezvous_id().unwrap(),
            &operation,
            &authority,
            &proof,
            100,
        ),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    ));
    duplicate
        .register(&operation, &authority, &proof, 100)
        .unwrap();
    assert!(matches!(
        duplicate.register(&operation, &authority, &proof, 100),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    ));
    let rendezvous_id = first.broker_rendezvous_id().unwrap();
    for (candidate, now) in [
        (&foreign_session, 100),
        (&foreign_release, 100),
        (&authority, 4_000_000_000),
    ] {
        let registry = super::super::broker::pending::PendingBrokerRendezvousRegistry::new(
            handles.duplicate(),
        );
        registry.reserve_new_for_test(&authority, &proof);
        registry
            .register(&operation, &authority, &proof, 100)
            .unwrap();
        assert!(matches!(
            registry.begin_endpoint_handoff(rendezvous_id, &operation, candidate, &proof, now),
            Err(ProviderCredentialEnrollmentHostError::AccessDenied)
        ));
        assert!(!registry.has_live(operation.operation_id(), 100));
        assert!(matches!(
            registry.begin_endpoint_handoff(rendezvous_id, &operation, &authority, &proof, 100),
            Err(ProviderCredentialEnrollmentHostError::AccessDenied)
        ));
    }
    let substituted = CredentialOperationSnapshot::new(
        CredentialOperationId::from_bytes([9; 16]).unwrap(),
        operation.provider().clone(),
        operation.action(),
        operation.state(),
        operation.allocated_credential_version().cloned(),
        operation.target_credential_version().cloned(),
        operation.metadata().clone(),
    )
    .unwrap();
    let registry =
        super::super::broker::pending::PendingBrokerRendezvousRegistry::new(handles.duplicate());
    registry.reserve_new_for_test(&authority, &proof);
    registry
        .register(&operation, &authority, &proof, 100)
        .unwrap();
    assert!(!registry.has_live(operation.operation_id(), 0));
    assert!(matches!(
        registry.begin_endpoint_handoff(rendezvous_id, &substituted, &authority, &proof, 100),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    ));
    assert!(!registry.has_live(operation.operation_id(), 100));
}
