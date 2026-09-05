use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialBeginIntentBinding,
    ProviderCredentialCommandContext, ProviderCredentialEnrollmentActionV2,
    ProviderCredentialEnrollmentHostError, ProviderCredentialProviderV2,
    ProviderCredentialRequestAuthorityPair,
};
use runne_provider::{
    CredentialAuthorityPair, CredentialEnrollmentAuthorityPair, CredentialOperationSnapshot,
    CredentialVersionRef, ProviderCredentialEnrollmentStore, ProviderId,
};

use super::super::{
    CredentialEnrollmentReadback, ProviderCredentialAdmission,
    begin::ProviderCredentialEnrollmentBegin,
    broker::{
        pending::PendingBrokerRendezvousRegistry, rendezvous::DaemonOwnedUnixBrokerRendezvous,
    },
    operation_handle::ProviderCredentialOperationHandleIssuer,
};
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

fn seed_active_provider(path: &std::path::Path) {
    let connection = rusqlite::Connection::open(path).unwrap();
    let version = CredentialVersionRef::new(ProviderId::new("openai").unwrap(), 1).unwrap();
    connection
        .execute(
            "INSERT INTO provider_credential_operations (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, allocated_credential_version, allocated_ref_digest, state, begin_proof_digest, begin_proof_expires_at_high_water, qualified_release_tuple_digest, created_at, updated_at) VALUES (?1, ?2, 'openai', 'PAIR', ?1, 'seed-active', 1, 1, 1, ?3, 'PREPARED', ?4, 4000000000, ?5, 1, 1)",
            rusqlite::params![[78_u8; 16], [1_u8; 32], version.ref_digest(), [79_u8; 32], [80_u8; 32]],
        )
        .unwrap();
    connection.execute("UPDATE provider_credential_operations SET state='CLAIMED', continuation_binding_digest=?1, process_release_binding_digest=?2, updated_at=2 WHERE operation_id=?3", rusqlite::params![[81_u8; 32], [82_u8; 32], [78_u8; 16]]).unwrap();
    connection.execute("UPDATE provider_credential_operations SET state='NATIVE_EFFECT_OBSERVED', native_effect_disposition='created', updated_at=3 WHERE operation_id=?1", [[78_u8; 16]]).unwrap();
    connection.execute("UPDATE provider_credential_operations SET state='READBACK_VERIFIED', readback_observation_digest=?1, updated_at=4 WHERE operation_id=?2", rusqlite::params![[83_u8; 32], [78_u8; 16]]).unwrap();
    connection.execute("UPDATE provider_credential_authority_heads SET lifecycle_revision=2, credential_fence=2, readiness_revision=2, active_credential_version=1, active_ref_digest=?1, observed_at_high_water=4 WHERE provider_id='openai'", [version.ref_digest()]).unwrap();
    connection.execute("UPDATE provider_credential_operations SET state='COMPLETED', terminal_disposition='completed', updated_at=5 WHERE operation_id=?1", [[78_u8; 16]]).unwrap();
}

#[test]
fn prepared_revoke_replay_after_daemon_restart_restores_only_the_rendezvous() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("revoke-restart.sqlite");
    let (lifecycle_authority, _) = CredentialAuthorityPair::new().split();
    let (enrollment_authority, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let store =
        runne_store::provider::SqliteProviderCredentialLifecycleStore::open_with_authorities(
            &database,
            lifecycle_authority.clone(),
            enrollment_authority.clone(),
        )
        .unwrap();
    let provider = ProviderId::new("openai").unwrap();
    store.begin_admission_snapshot(&provider).unwrap();
    seed_active_provider(&database);

    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let command = BeginProviderCredentialEnrollment::new(
        ProviderCredentialEnrollmentActionV2::Revoke,
        ProviderCredentialProviderV2::OpenAi,
        2,
        "018f8d23-7f90-7c00-8000-000000000001",
        "revoke-restart",
        "revoke-restart-intent",
    )
    .unwrap();
    let context: ProviderCredentialCommandContext = context();
    let binding = ProviderCredentialBeginIntentBinding::new(&command, &context);
    let first_authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let first_proof = issuer
        .issue_intent_proof(
            [6; 32],
            [3; 32],
            *binding.action_provider_revision_digest(),
            *binding.command_identity_digest(),
            4_000_000_000,
        )
        .unwrap();
    let handles = ProviderCredentialOperationHandleIssuer::new([9; 32]);
    let first_registry = PendingBrokerRendezvousRegistry::new(handles.duplicate());
    first_registry.reserve_new_for_test(&first_authority, &first_proof);
    let reader = NoReadback;
    let first_begin = ProviderCredentialEnrollmentBegin::new(
        ProviderCredentialAdmission::new(verifier.clone(), measurements.clone()),
        handles.duplicate(),
        &store,
        &reader,
        first_registry,
    );
    let first = first_begin
        .admit(&first_authority, &first_proof, &context, &command, 100)
        .unwrap();
    let operation_id = handles.resolve(first.operation_handle()).unwrap();
    let fenced = store.lifecycle_snapshot(&provider).unwrap();
    assert_eq!(fenced.lifecycle_revision().get(), 3);
    assert_eq!(fenced.fence().get(), 3);
    drop(first_begin);
    drop(store);

    let store =
        runne_store::provider::SqliteProviderCredentialLifecycleStore::open_with_authorities(
            &database,
            lifecycle_authority,
            enrollment_authority,
        )
        .unwrap();

    let (restart_issuer, restart_verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let restart_authority = restart_issuer
        .issue_base([1; 32], [2; 32], [7; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let restart_proof = restart_issuer
        .issue_intent_proof(
            [8; 32],
            [7; 32],
            *binding.action_provider_revision_digest(),
            *binding.command_identity_digest(),
            4_000_000_000,
        )
        .unwrap();
    let restart_handles = ProviderCredentialOperationHandleIssuer::new([10; 32]);
    let restart_registry = PendingBrokerRendezvousRegistry::new(restart_handles.duplicate());
    let restart_begin = ProviderCredentialEnrollmentBegin::new(
        ProviderCredentialAdmission::new(restart_verifier, measurements),
        restart_handles.duplicate(),
        &store,
        &reader,
        restart_registry.clone(),
    );

    let mismatched_command = BeginProviderCredentialEnrollment::new(
        ProviderCredentialEnrollmentActionV2::Pair,
        ProviderCredentialProviderV2::OpenAi,
        2,
        "018f8d23-7f90-7c00-8000-000000000001",
        "revoke-restart",
        "mismatched-replay-intent",
    )
    .unwrap();
    let mismatched_binding =
        ProviderCredentialBeginIntentBinding::new(&mismatched_command, &context);
    let mismatched_proof = restart_issuer
        .issue_intent_proof(
            [13; 32],
            [7; 32],
            *mismatched_binding.action_provider_revision_digest(),
            *mismatched_binding.command_identity_digest(),
            4_000_000_000,
        )
        .unwrap();
    restart_registry.reserve_new_for_test(&restart_authority, &mismatched_proof);
    assert!(matches!(
        restart_begin.admit(
            &restart_authority,
            &mismatched_proof,
            &context,
            &mismatched_command,
            101,
        ),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    ));
    assert!(
        restart_registry
            .reserve_transition_rendezvous(
                DaemonOwnedUnixBrokerRendezvous::create().unwrap(),
                &restart_authority,
                &restart_proof,
            )
            .is_ok(),
        "a rejected replay must release its matching transition reservation"
    );
    let replay = restart_begin
        .admit(&restart_authority, &restart_proof, &context, &command, 101)
        .unwrap();

    assert_ne!(replay.operation_handle(), first.operation_handle());
    assert_eq!(
        restart_handles.resolve(replay.operation_handle()),
        Ok(operation_id)
    );
    let after = store.lifecycle_snapshot(&provider).unwrap();
    assert_eq!(after.lifecycle_revision(), fenced.lifecycle_revision());
    assert_eq!(after.fence(), fenced.fence());
    let operation = store.load_operation(operation_id).unwrap();
    restart_registry
        .begin_endpoint_handoff(
            replay.broker_rendezvous_id().unwrap(),
            &operation,
            &restart_authority,
            &restart_proof,
            101,
        )
        .unwrap();

    let second_authority = restart_issuer
        .issue_base([1; 32], [2; 32], [11; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let second_proof = restart_issuer
        .issue_intent_proof(
            [12; 32],
            [11; 32],
            *binding.action_provider_revision_digest(),
            *binding.command_identity_digest(),
            4_000_000_000,
        )
        .unwrap();
    restart_registry.reserve_new_for_test(&second_authority, &second_proof);
    let detached_replay = restart_begin
        .admit(&second_authority, &second_proof, &context, &command, 102)
        .unwrap();
    assert_eq!(
        restart_handles.resolve(detached_replay.operation_handle()),
        Ok(operation_id)
    );
    assert_eq!(detached_replay.broker_rendezvous_id(), None);
    assert!(matches!(
        restart_registry
            .begin_gate(102)
            .unwrap()
            .preflight(&second_authority, &second_proof),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    ));
}
