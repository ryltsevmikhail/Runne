use super::*;
use crate::project_workspace_sqlite::unknown_successor::fixture::Fixture;
use runne_application::ports::EventStore;
use runne_application::provider::ProviderCoordinatorRequest;
use runne_provider::ProviderResponseIdentityCommitter;
use runne_store::provider::{
    CredentialDispatchAuthority, ProviderCoordinatorOutcome, SqliteProviderDispatchCoordinator,
};
#[path = "producer/coordinator_effect.rs"]
mod coordinator_effect;
use coordinator_effect::PersistRequestAndStartStream;

pub(in super::super) fn completed_before_unknown(name: &str, tail: u8) -> Prepared {
    let fixture =
        super::super::super::super::fixture::running_without_provider_admission(name, tail);
    let provider_id = ProviderId::new("fixture-provider").unwrap();
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([tail; 16]),
        ModelRef::new(provider_id.clone(), "fixture-model", "v1").unwrap(),
        [5; 32],
        1_024,
        serde_json::Value::Null,
    )
    .unwrap();
    let call_id = call.call_id();
    let rendered = PreparedRequest::from_call(&call).unwrap();
    let dispatch = crate::validated_reopen::open_provider_dispatch(
        fixture.database.file.path(),
        fixture.database.identity,
    )
    .unwrap();
    let response_id = format!("resp_{name}");
    let effect = PersistRequestAndStartStream {
        execution: Arc::clone(&fixture.execution),
        response_id: response_id.clone(),
    };
    let guard = crate::project_workspace_sqlite::support::guard();
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &dispatch,
        &fixture.execution,
        CredentialDispatchAuthority::new(&fixture.credentials, &fixture.launch),
        &crate::project_workspace_sqlite::unknown_successor::effect::Adapter,
        &effect,
        guard.as_ref(),
    );
    let outcome = futures::executor::block_on(coordinator.dispatch(ProviderCoordinatorRequest {
        call,
        principal_id: "principal-1".into(),
        conversation_id: conversation_id(&fixture),
        taskrun_id: fixture.taskrun_id,
        execution_attempt_id: fixture.claim_identity.attempt_id,
        profile_digest: [2; 32],
        pricing_revision_digest: [3; 32],
        requested_input_tokens: 512,
        requested_output_tokens: 1_024,
        max_cost_micros: 50_000,
        currency: "USD".into(),
        provider_idempotency_key: format!("strict-v59-{name}"),
    }))
    .unwrap();
    assert!(matches!(
        outcome,
        ProviderCoordinatorOutcome::Streaming { .. }
    ));
    fixture
        .database
        .store
        .bind_prepared_taskrun_provider_effect(BindPreparedTaskRunProviderEffect {
            identity: fixture.claim_identity.clone(),
            expected_claim_version: 4,
            prepared: PreparedTaskRunProviderRequest {
                call_id,
                call_digest_version: rendered.request_ref().digest_version(),
                prepared_digest: *rendered.request_ref().as_bytes(),
                render_digest: *rendered.render_digest(),
                profile_digest: [2; 32],
                provider_idempotency_key: format!("strict-v59-{name}"),
            },
        })
        .unwrap();
    let attempt = attempt(&fixture);
    let binding = fixture
        .execution
        .load_remote_attempt(attempt)
        .unwrap()
        .unwrap()
        .request
        .binding;
    let recovery = ProviderRecoveryBinding::new(
        binding.taskrun_id,
        binding.taskrun_attempt_id,
        binding.dispatch_attempt_id,
        binding.profile_digest,
    )
    .unwrap();
    let committer = Arc::new(RuntimeProviderRemoteIdentityCommitter::new(
        Arc::new(super::super::super::super::effect::Keyring),
        Arc::clone(&fixture.execution),
    ));
    let response_id = RemoteResponseId::new(&response_id).unwrap();
    let proof = fixture
        .execution
        .issue_remote_operation_proof(
            &binding,
            &response_id,
            runne_provider::ProviderRecoveryOperation::StatusCheck,
        )
        .unwrap();
    let status = ProviderRemoteResponseStatus::Completed {
        usage: Some(ProviderUsage::new(3, 4, 0, 0).unwrap()),
    };
    let artifact = ProviderRemoteTerminalArtifact::new(
        response_id.clone(),
        status.clone(),
        Some("strict v59 output".into()),
    )
    .unwrap();
    let check = ProviderRemoteCheck::new_authorized(
        recovery,
        response_id,
        status,
        Some(artifact),
        runne_provider::ProviderRecoveryOperation::StatusCheck,
        proof,
    )
    .unwrap();
    futures::executor::block_on(committer.persist_remote_check(&check)).unwrap();
    assert_eq!(
        committer
            .commit_authenticated_remote_terminal_source(recovery, &Price)
            .unwrap(),
        ProviderRemoteTerminalSourceOutcome::CurrentGeneration
    );
    let artifact_digest = *fixture
        .execution
        .load_remote_attempt(binding.dispatch_attempt_id)
        .unwrap()
        .unwrap()
        .terminal
        .unwrap()
        .encrypted_artifact
        .plaintext_digest();
    Prepared {
        fixture,
        attempt: binding.dispatch_attempt_id,
        recovery,
        committer,
        artifact_digest,
    }
}

pub(super) fn conversation_id(fixture: &Fixture) -> runne_domain::id::ConversationId {
    fixture
        .database
        .store
        .load_task_run(fixture.taskrun_id)
        .unwrap()
        .events
        .iter()
        .find_map(|event| match event.payload() {
            runne_domain::task_run::TaskRunEvent::TaskRunSubmitted {
                conversation_id, ..
            } => Some(*conversation_id),
            _ => None,
        })
        .unwrap()
}

fn attempt(fixture: &Fixture) -> runne_provider::DispatchAttemptId {
    let bytes: Vec<u8> = fixture
        .database
        .connection()
        .query_row(
            "SELECT dispatch_attempt_id FROM provider_execution_admissions WHERE taskrun_id=?1",
            [fixture.taskrun_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    runne_provider::DispatchAttemptId::from_bytes(bytes.try_into().unwrap())
}

pub(in super::super) fn assert_dispatch_source(
    prepared: &Prepared,
    dispatch_state: i64,
    source_state: i64,
    outbox_state: i64,
) {
    let actual: (i64, i64, i64, Option<Vec<u8>>, Option<i64>) = prepared
        .fixture
        .database
        .connection()
        .query_row(
            "SELECT d.state,s.settlement_state,o.state,o.receipt_digest,o.applied_at
             FROM provider_dispatch_attempts d
             JOIN provider_remote_terminal_settlements s ON s.dispatch_attempt_id=d.attempt_id
             JOIN provider_terminal_outbox o ON o.dispatch_attempt_id=d.attempt_id
             WHERE d.attempt_id=?1",
            [prepared.attempt.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        (actual.0, actual.1, actual.2),
        (dispatch_state, source_state, outbox_state)
    );
    if outbox_state == 1 {
        assert!(actual.3.is_none());
        assert!(actual.4.is_none());
    } else {
        assert!(actual.3.is_some());
        assert!(actual.4.is_some());
    }
}
