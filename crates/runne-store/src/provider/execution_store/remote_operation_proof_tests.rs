use super::super::credential_lifecycle::online_test_support::complete_pair;
use super::ProviderAuthorityIssueOutcome;
use super::ProviderRemoteObservationState;
use super::authority_test_support::{Fixture, prepare_request_for_provider};
use super::secondary_profile_grant_tests;
use runne_application::provider::{ProviderExecutionStore, ProviderRemoteRecoveryStore};
use runne_provider::{
    ModelRef, PreparedRequest, ProviderCall, ProviderCallId, ProviderId,
    ProviderRecoveryAttemptIdentity, ProviderRecoveryBinding,
    ProviderRecoveryDispatchContextProvider, ProviderRecoveryOperation, ProviderRemoteCheck,
    ProviderRemoteResponseStatus, ProviderResponseIdentityCommitter, RemoteResponseId,
};
use runne_runtime::provider_execution::RuntimeProviderRemoteIdentityCommitter;
use runne_secure_store::ProviderJournalKeyRef;
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[path = "remote_operation_proof_tests/observation_projection.rs"]
mod observation_projection;
#[path = "remote_operation_proof_tests/taskrun_setup.rs"]
mod taskrun_setup;
use taskrun_setup::TestKeyring;

#[test]
fn remote_operation_proof_is_reserved_exactly_once_and_consumed_by_observation() {
    let (mut fixture, lifecycle) = Fixture::new_with_online_credentials(100, |store| {
        complete_pair(store, 81, "remote-proof-online");
    });
    fixture.config.profile_digest = [22; 32];
    fixture.config.pricing_revision_digest = [33; 32];
    taskrun_setup::initialize_identity(&fixture.path, fixture.config.runtime_authority_id);
    fixture.install();
    let grant = secondary_profile_grant_tests::grant(&fixture, "openai");
    let mut request = prepare_request_for_provider(fixture.launch(), &fixture.path, 82, "openai");
    let (conversation_id, taskrun_id, attempt_id) =
        taskrun_setup::submit_and_claim(&fixture.path, fixture.config.runtime_authority_id);
    request.conversation_id = conversation_id;
    request.taskrun_id = taskrun_id;
    request.execution_attempt_id = attempt_id;
    let admission = match fixture
        .store
        .issue_secondary_profile(fixture.launch(), &grant, &request)
        .unwrap()
    {
        ProviderAuthorityIssueOutcome::Winner(value) => value,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("fresh admission expected"),
    };
    let authorization = lifecycle
        .authorize_online_dispatch(fixture.launch(), admission.claim(), 100)
        .unwrap();
    let (_, credential) = authorization.split();
    fixture
        .store
        .start_online_effect(fixture.launch(), admission.claim(), &credential)
        .unwrap();
    let binding = fixture
        .store
        .resolve_remote_attempt_binding(
            admission.claim(),
            &ProviderId::new("openai").unwrap(),
            &ProviderId::new("openai").unwrap(),
            "background-text-v1",
        )
        .unwrap();
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([82; 16]),
        ModelRef::new(ProviderId::new("openai").unwrap(), "fixture-model", "v1").unwrap(),
        [5; 32],
        1_024,
        serde_json::Value::Null,
    )
    .unwrap();
    let rendered = PreparedRequest::from_call(&call).unwrap();
    let identity = ProviderRecoveryAttemptIdentity::new(
        ProviderId::new(&binding.provider_id).unwrap(),
        ProviderId::new(&binding.credential_realm).unwrap(),
        binding.profile_id.clone(),
        binding.profile_digest,
        binding.semantic_digest,
        binding.prepared_digest,
        binding.pricing_digest,
        binding.request_digest,
        binding.runtime_authority_id,
        binding.database_generation,
        binding.runtime_generation,
        binding.fencing_token,
    )
    .unwrap();
    let recovery = ProviderRecoveryBinding::new(
        binding.taskrun_id,
        binding.taskrun_attempt_id,
        binding.dispatch_attempt_id,
        binding.profile_digest,
    )
    .unwrap();
    let key = fixture.store.active_journal_key_binding().unwrap().unwrap();
    let key_ref = ProviderJournalKeyRef::new(
        key.key_id(),
        key.key_version(),
        key.runtime_authority_id(),
        key.database_generation(),
    )
    .unwrap();
    let keyring = Arc::new(TestKeyring(key_ref));
    let store = Arc::new(fixture.store);
    let contexts =
        RuntimeProviderRemoteIdentityCommitter::new(Arc::clone(&keyring), Arc::clone(&store));
    let provider = ProviderId::new("openai").unwrap();
    let context = futures::executor::block_on(contexts.for_new_dispatch(
        admission.claim(),
        &provider,
        &provider,
        "background-text-v1",
    ))
    .unwrap();
    assert_eq!(context.binding(), recovery);
    assert_eq!(context.identity(), Some(&identity));
    futures::executor::block_on(context.persist_request(rendered.rendered_bytes())).unwrap();
    assert!(
        futures::executor::block_on(contexts.for_new_dispatch(
            admission.claim(),
            &provider,
            &provider,
            "background-text-v1",
        ))
        .is_err(),
        "a durable intent must prevent a second create context"
    );
    let remote_id = RemoteResponseId::new("resp_proof_82").unwrap();
    futures::executor::block_on(contexts.commit(recovery, &remote_id)).unwrap();
    let page = store.scan_remote_attempts(None, 8).unwrap();
    assert_eq!(page.attempts, vec![binding.dispatch_attempt_id]);
    assert!(page.reached_end);
    assert_eq!(
        store
            .find_remote_attempt(binding.taskrun_id, binding.taskrun_attempt_id)
            .unwrap(),
        Some(binding.dispatch_attempt_id)
    );
    let first_page = store.scan_remote_attempts(None, 1).unwrap();
    assert_eq!(first_page.next_after, Some(binding.dispatch_attempt_id));
    let exhausted = store
        .scan_remote_attempts(first_page.next_after, 1)
        .unwrap();
    assert!(exhausted.attempts.is_empty());
    assert!(exhausted.reached_end);

    let proof = store
        .issue_remote_operation_proof(&binding, &remote_id, ProviderRecoveryOperation::StatusCheck)
        .unwrap();

    assert_eq!(
        observation_projection::effects_observation_at(&store, &binding, 101),
        runne_application::provider::ProviderRemoteObservationProjection::Unknown
    );
    let connection = store.connection.lock().unwrap();
    let outstanding =
        super::read_remote_observation_in_transaction(&connection, &binding, 101).unwrap();
    assert_eq!(
        outstanding.state,
        ProviderRemoteObservationState::Outstanding
    );
    let expired =
        super::read_remote_observation_in_transaction(&connection, &binding, 130).unwrap();
    assert_eq!(expired.state, ProviderRemoteObservationState::Expired);
    drop(connection);
    assert_eq!(
        observation_projection::effects_observation_at(&store, &binding, 130),
        runne_application::provider::ProviderRemoteObservationProjection::Unknown
    );
    assert!(
        store
            .issue_remote_operation_proof(
                &binding,
                &remote_id,
                ProviderRecoveryOperation::StatusCheck
            )
            .is_err()
    );
    assert!(!proof.matches(
        recovery,
        ProviderRecoveryOperation::RemoteCancel,
        &remote_id
    ));
    let check = ProviderRemoteCheck::new_authorized(
        recovery,
        remote_id.clone(),
        ProviderRemoteResponseStatus::Pending,
        None,
        ProviderRecoveryOperation::StatusCheck,
        proof.clone(),
    )
    .unwrap();
    futures::executor::block_on(contexts.persist_remote_check(&check)).unwrap();
    assert!(
        store
            .commit_remote_operation_observation(&proof, ProviderRemoteResponseStatus::Pending,)
            .is_err()
    );
    let consumed: (i64, i64) = store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT state,observation_status FROM provider_remote_operation_proofs WHERE nonce=?1",
            [proof.nonce().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(consumed, (2, 1));
    let connection = store.connection.lock().unwrap();
    let pending =
        super::read_remote_observation_in_transaction(&connection, &binding, 101).unwrap();
    assert_eq!(pending.state, ProviderRemoteObservationState::Pending);
    assert_eq!(pending.status, ProviderRemoteResponseStatus::Pending);
    drop(connection);
    assert_eq!(
        observation_projection::effects_observation_at(&store, &binding, 101),
        runne_application::provider::ProviderRemoteObservationProjection::Pending
    );
    assert_eq!(
        observation_projection::effects_observation_at(&store, &binding, 99),
        runne_application::provider::ProviderRemoteObservationProjection::Unknown
    );
    assert_eq!(
        observation_projection::effects_observation_at(&store, &binding, 701),
        runne_application::provider::ProviderRemoteObservationProjection::Unknown
    );
    let unknown = store
        .issue_remote_operation_proof(&binding, &remote_id, ProviderRecoveryOperation::StatusCheck)
        .unwrap();
    let connection = store.connection.lock().unwrap();
    let pending_while_polling =
        super::read_remote_observation_in_transaction(&connection, &binding, 102).unwrap();
    assert_eq!(
        pending_while_polling.state,
        ProviderRemoteObservationState::Outstanding
    );
    assert_eq!(
        pending_while_polling.status,
        ProviderRemoteResponseStatus::Pending
    );
    drop(connection);
    store
        .commit_remote_operation_observation(&unknown, ProviderRemoteResponseStatus::Unknown)
        .unwrap();
    let status: i64 = store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT observation_status FROM provider_remote_operation_proofs WHERE nonce=?1",
            [unknown.nonce().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(status, 2);
    assert_eq!(
        Sha256::digest(remote_id.as_str().as_bytes()).as_slice(),
        proof.response_id_digest()
    );
    assert_eq!(binding.taskrun_id, request.taskrun_id);
}
