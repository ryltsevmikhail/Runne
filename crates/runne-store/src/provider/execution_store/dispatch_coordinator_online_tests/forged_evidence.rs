use std::sync::atomic::Ordering;

use futures::executor::block_on;
use runne_application::provider::{ProviderAdmissionError, ProviderCoordinatorRequest};
use runne_provider::{ModelRef, ProviderCall, ProviderCallId, ProviderId, ProviderRepositoryState};
use rusqlite::Connection;
use rusqlite::functions::FunctionFlags;

use super::{Effect, Guard, online_counts};
use crate::provider::credential_lifecycle::online_claim_test_support::reopen_test_store;
use crate::provider::credential_lifecycle::online_test_support::complete_pair;
use crate::provider::execution_store::authority_test_support::{
    Fixture, configured_connection, prepare_request_for_provider,
};
use crate::provider::{
    CredentialDispatchAuthority, ProviderCoordinatorOutcome, SqliteProviderDispatchCoordinator,
    SqliteProviderDispatchStore,
};

#[test]
fn raw_forged_v26_proof_never_yields_receipt_or_adapter_call() {
    let fixture = Fixture::new(100);
    fixture.install();
    let path = &fixture.path;
    let lifecycle = reopen_test_store(path, 100);
    complete_pair(&lifecycle, 83, "forged-proof");
    let request = prepare_request_for_provider(fixture.launch(), path, 83, "openai");
    let admission = match fixture.store.issue(fixture.launch(), &request).unwrap() {
        crate::provider::ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        crate::provider::ProviderAuthorityIssueOutcome::Existing { .. } => panic!("fresh issue"),
    };
    let coordinator_request = coordinator_request(path);
    let dispatch = SqliteProviderDispatchStore::open_with_connection(
        path.to_str().unwrap(),
        configured_connection(path),
    )
    .unwrap();

    forge_evidence(path);
    let claim = admission.into_claim();
    let binding = lifecycle
        .authorize_online_dispatch(fixture.launch(), &claim, 100)
        .unwrap();
    let (_, effect_binding) = binding.split();
    let forged = fixture
        .store
        .start_online_effect(fixture.launch(), &claim, &effect_binding);
    assert!(
        matches!(forged, Err(ProviderAdmissionError::AuthorityDenied)),
        "forged proof must fail current effect verification: {forged:?}"
    );
    assert_eq!(online_counts(path), (0, 0, 0));

    let effect = Effect::default();
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &dispatch,
        &fixture.store,
        CredentialDispatchAuthority::new(&lifecycle, fixture.launch()),
        &effect,
        &effect,
        &Guard,
    );
    assert_eq!(
        block_on(coordinator.dispatch(coordinator_request)).unwrap(),
        ProviderCoordinatorOutcome::Existing {
            state: ProviderRepositoryState::Dispatching,
        }
    );
    assert_eq!(effect.materialized.load(Ordering::SeqCst), 0);
    assert_eq!(effect.dispatched_count(), 0);
    assert_eq!(online_counts(path), (0, 0, 0));
}

fn forge_evidence(path: &std::path::Path) {
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch(
            "DROP TRIGGER provider_online_dispatch_issuance_evidence_no_delete;
             DROP TRIGGER provider_online_dispatch_claim_provider_no_delete;
             DELETE FROM provider_online_dispatch_claim_providers;
             DELETE FROM provider_online_dispatch_issuance_evidence;",
        )
        .unwrap();
    connection
        .create_scalar_function(
            "runne_online_issuance_guard",
            5,
            FunctionFlags::SQLITE_UTF8,
            |_| Ok(true),
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO provider_online_dispatch_issuance_evidence
             (dispatch_attempt_id, provider_id, authority_id, authority_revision, issued_at,
              proof_version, journal_key_id, journal_key_version,
              journal_runtime_authority_id, journal_database_generation, issuance_mac)
             SELECT dispatch_attempt_id, 'openai', authority_id, authority_revision, issued_at,
                    1, ?1, 1, ?2, 7, ?3 FROM provider_execution_admissions",
            rusqlite::params![vec![9_u8; 16], vec![1_u8; 16], vec![6_u8; 32]],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO provider_online_dispatch_claim_providers
             (dispatch_attempt_id, provider_id)
             SELECT dispatch_attempt_id, 'openai' FROM provider_execution_admissions",
            [],
        )
        .unwrap();
}

fn coordinator_request(path: &std::path::Path) -> ProviderCoordinatorRequest {
    let (conversation_id, taskrun_id, execution_attempt_id) =
        super::super::canonical_started_test_support::seed(path, 83);
    ProviderCoordinatorRequest {
        call: ProviderCall::new(
            ProviderCallId::from_bytes([83; 16]),
            ModelRef::new(ProviderId::new("openai").unwrap(), "fixture-model", "v1").unwrap(),
            [5; 32],
            1_024,
            serde_json::Value::Null,
        )
        .unwrap(),
        principal_id: "principal-1".into(),
        conversation_id,
        taskrun_id,
        execution_attempt_id,
        profile_digest: [2; 32],
        pricing_revision_digest: [3; 32],
        requested_input_tokens: 512,
        requested_output_tokens: 1_024,
        max_cost_micros: 50_000,
        currency: "USD".into(),
        provider_idempotency_key: "provider-v14-83".into(),
    }
}
