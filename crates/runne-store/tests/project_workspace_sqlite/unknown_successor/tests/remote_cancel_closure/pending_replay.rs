use super::support::Price;
use runne_application::commands::CancelTaskRunInput;
use runne_application::conversation_text_service::ConversationTextService;
use runne_application::ports::{ConversationRepository, RuntimeAuthorityId};
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_application::provider::ProviderRemoteRecoveryStore;
use runne_application::service::TaskRunService;
use runne_provider::{
    DispatchAttemptId, ProviderRecoveryBinding, ProviderRecoveryOperation, ProviderRemoteCheck,
    ProviderRemoteResponseStatus, ProviderRemoteTerminalArtifact,
    ProviderResponseIdentityCommitter, ProviderStreamEvent, ProviderUsage, RemoteResponseId,
    ScannerTerminalDisposition,
};
use runne_runtime::provider_execution::{
    ConversationProviderTerminalApplication, ProviderEventJournalContext,
    ProviderRemoteTerminalSourceOutcome, ProviderTerminalOutboxApplication,
    RuntimeProviderExecution, RuntimeProviderRemoteIdentityCommitter,
};
use runne_runtime::provider_redaction::{
    PreJournalProviderEvent, ProviderEventRedaction, ProviderRedactionError,
};
use std::sync::Arc;

struct NoopRedaction;

impl ProviderEventRedaction for NoopRedaction {
    fn scan_before_journal(
        &self,
        _: &ProviderEventJournalContext,
        event: &ProviderStreamEvent,
    ) -> Result<PreJournalProviderEvent, ProviderRedactionError> {
        Ok(PreJournalProviderEvent::Append(event.clone()))
    }

    fn terminal_disposition(
        &self,
        _: DispatchAttemptId,
    ) -> Result<Option<ScannerTerminalDisposition>, ProviderRedactionError> {
        Ok(None)
    }
}

#[test]
fn remote_cancellation_commit_replays_and_acks_after_reopen() {
    let fixture = super::super::super::fixture::running_with_remote_id(
        "remote-cancel-pending-ack",
        0x44,
        "resp_cancel_pending_ack",
    );
    let dispatch_attempt_id = super::support::attempt(&fixture);
    let snapshot = fixture
        .execution
        .load_remote_attempt(dispatch_attempt_id)
        .unwrap()
        .unwrap();
    let binding = snapshot.request.binding.clone();
    let authority = RuntimeAuthorityId(
        binding
            .runtime_authority_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    );
    let recovery = ProviderRecoveryBinding::new(
        binding.taskrun_id,
        binding.taskrun_attempt_id,
        dispatch_attempt_id,
        binding.profile_digest,
    )
    .unwrap();
    let keyring = Arc::new(super::super::super::effect::Keyring);
    let committer = RuntimeProviderRemoteIdentityCommitter::new(
        Arc::clone(&keyring),
        Arc::clone(&fixture.execution),
    );
    let response_id = RemoteResponseId::new("resp_cancel_pending_ack").unwrap();
    let proof = fixture
        .execution
        .issue_remote_operation_proof(
            &binding,
            &response_id,
            ProviderRecoveryOperation::StatusCheck,
        )
        .unwrap();
    let status = ProviderRemoteResponseStatus::Completed {
        usage: Some(ProviderUsage::new(5, 7, 0, 0).unwrap()),
    };
    let artifact = ProviderRemoteTerminalArtifact::new(
        response_id.clone(),
        status.clone(),
        Some("completed after accepted cancellation".into()),
    )
    .unwrap();
    let check = ProviderRemoteCheck::new_authorized(
        recovery,
        response_id,
        status,
        Some(artifact),
        ProviderRecoveryOperation::StatusCheck,
        proof,
    )
    .unwrap();
    futures::executor::block_on(committer.persist_remote_check(&check)).unwrap();
    assert_eq!(
        committer
            .commit_authenticated_remote_terminal_source(recovery, &Price)
            .unwrap(),
        ProviderRemoteTerminalSourceOutcome::CurrentGeneration,
    );

    TaskRunService::new(
        fixture.database.store.clone(),
        fixture.database.store.clone(),
        fixture.database.store.clone(),
        authority.clone(),
    )
    .cancel_task_run(
        &super::context(0xe5, "remote-cancel-pending-ack"),
        CancelTaskRunInput {
            taskrun_id: fixture.taskrun_id,
            expected_version: fixture.version,
        },
    )
    .unwrap();

    let guard: Arc<dyn ProhibitedContentPort> = super::guard();
    let runtime = RuntimeProviderExecution::new(
        keyring.as_ref(),
        fixture.execution.as_ref(),
        &Price,
        guard.as_ref(),
        &NoopRedaction,
    );
    let text = ConversationTextService::new(
        fixture.database.store.clone(),
        fixture.database.store.clone(),
        authority.clone(),
        Arc::clone(&guard),
    );
    let application = ConversationProviderTerminalApplication::new(
        fixture.database.store.clone(),
        Arc::new(text),
    );
    let pending = runtime.recover_pending_terminal_outputs().unwrap();
    assert_eq!(pending.len(), 1);
    let first_ack = application
        .complete_provider_terminal_cancellation(pending[0].record(), pending[0].output())
        .unwrap();
    assert_ne!(first_ack, [0; 32]);
    assert_eq!(pending_state(&fixture, dispatch_attempt_id), 1);

    let reopened = crate::validated_reopen::reopen_store(
        fixture.database.file.path(),
        fixture.database.identity,
        authority.clone(),
        super::guard(),
    )
    .unwrap();
    let replay_text = ConversationTextService::new(
        reopened.clone(),
        reopened.clone(),
        authority,
        super::guard(),
    );
    let replay_application =
        ConversationProviderTerminalApplication::new(reopened.clone(), Arc::new(replay_text));
    let reopened_execution = Arc::new(
        crate::validated_reopen::open_provider_execution(
            fixture.database.file.path(),
            fixture.database.identity,
        )
        .unwrap(),
    );
    let replay_runtime = RuntimeProviderExecution::new(
        keyring.as_ref(),
        reopened_execution.as_ref(),
        &Price,
        guard.as_ref(),
        &NoopRedaction,
    );
    let replay = replay_runtime.recover_pending_terminal_outputs().unwrap();
    assert_eq!(replay.len(), 1);
    let resolved = runne_runtime::provider_execution::ProviderTerminalConversationResolver::resolve_provider_terminal_conversation(
        &reopened,
        replay[0].record(),
    )
    .unwrap();
    assert_eq!(
        resolved.started.phase,
        runne_application::ports::TextGenerationPhase::Started
    );
    let replay_ack = replay_application
        .complete_provider_terminal_cancellation(replay[0].record(), replay[0].output())
        .unwrap();
    assert_eq!(replay_ack, first_ack);
    replay_runtime
        .acknowledge_terminal_output(replay[0].record().outbox_id, replay_ack)
        .unwrap();
    assert_eq!(pending_state(&fixture, dispatch_attempt_id), 2);
    let historical = reopened_execution
        .load_remote_attempt_history(fixture.taskrun_id, fixture.claim_identity.attempt_id)
        .unwrap()
        .expect("acknowledged remote history remains readable");
    assert!(historical.response.is_some());
    assert!(historical.terminal.is_some());
    assert!(
        fixture
            .database
            .store
            .load_conversation(resolved.started.conversation_id)
            .unwrap()
            .events
            .iter()
            .all(|event| !matches!(
                event.payload(),
                runne_domain::conversation::ConversationEvent::AssistantMessageAppended {
                    taskrun_id, ..
                } if *taskrun_id == fixture.taskrun_id
            ))
    );
}

fn pending_state(
    fixture: &super::super::super::fixture::Fixture,
    attempt: DispatchAttemptId,
) -> i64 {
    fixture
        .database
        .connection()
        .query_row(
            "SELECT state FROM provider_terminal_outbox WHERE dispatch_attempt_id=?1",
            [attempt.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap()
}
