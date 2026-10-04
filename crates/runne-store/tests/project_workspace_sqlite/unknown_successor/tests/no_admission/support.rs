use super::*;
use runne_application::service::TaskRunService;

pub(super) fn close_cancelled_without_admission(
    database: &Database,
    begin_context: runne_application::ports::ApplicationCommandContext,
    started: runne_application::ports::TextGenerationReceipt,
    prompt: &str,
    cancellation_version: u64,
) {
    let text = ConversationTextService::new(
        database.store.clone(),
        database.store.clone(),
        super::super::super::fixture::runtime_authority(),
        guard(),
    );
    let receipt = text
        .finish_text(
            &begin_context,
            FinishConversationTextInput {
                original: BeginConversationTextInput {
                    conversation_id: started.conversation_id,
                    expected_version: started.conversation_version - 1,
                    text: MessageText::new(prompt.to_owned()).unwrap(),
                },
                started,
                completion: ConversationTextCompletion::NoProviderAdmissionCancellation {
                    evidence: runne_application::ports::ProviderNoAdmissionCancellationEvidence {
                        cancellation_taskrun_version: cancellation_version,
                    },
                },
            },
        )
        .unwrap();
    assert_eq!(
        receipt.phase,
        runne_application::ports::TextGenerationPhase::Rejected
    );
}

pub(super) fn request_cancel(
    database: &Database,
    started: &runne_application::ports::TextGenerationReceipt,
) -> u64 {
    TaskRunService::new(
        database.store.clone(),
        database.store.clone(),
        database.store.clone(),
        super::super::super::fixture::runtime_authority(),
    )
    .cancel_task_run(
        &context(0x64, "no-admission-cancel"),
        CancelTaskRunInput {
            taskrun_id: started.taskrun_id,
            expected_version: started.taskrun_version,
        },
    )
    .unwrap();
    started.taskrun_version + 1
}

pub(super) fn assert_fresh_issue_denied(
    database: &Database,
    execution: &runne_store::provider::SqliteProviderExecutionStore,
    launch: &runne_store::provider::ProviderRuntimeLaunchCapability,
    started: &runne_application::ports::TextGenerationReceipt,
    principal_id: &str,
) {
    let request = fresh_issue_request(started, principal_id);
    let dispatch =
        crate::validated_reopen::open_provider_dispatch(database.file.path(), database.identity)
            .unwrap();
    dispatch
        .persist_prepared(
            launch,
            &runne_store::provider::PreparedProviderRecord {
                call_id: request.prepared.call_id,
                call_digest_version: request.prepared.call_digest_version,
                prepared_digest: request.prepared.prepared_digest,
                render_digest: request.prepared.render_digest,
                profile_digest: request.prepared.profile_digest,
            },
        )
        .unwrap();
    assert!(matches!(
        execution.issue(launch, &request),
        Err(runne_application::provider::ProviderAdmissionError::AuthorityDenied)
    ));
}

pub(super) fn fresh_issue_request(
    started: &runne_application::ports::TextGenerationReceipt,
    principal_id: &str,
) -> runne_application::provider::ProviderAuthorityIssueRequest {
    use runne_provider::{ModelRef, PreparedRequest, ProviderCall, ProviderCallId, ProviderId};
    let provider_id = ProviderId::new("fixture-provider").unwrap();
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([0xd4; 16]),
        ModelRef::new(provider_id.clone(), "fixture-model", "v1").unwrap(),
        [5; 32],
        1_024,
        serde_json::Value::Null,
    )
    .unwrap();
    let prepared = PreparedRequest::from_call(&call).unwrap();
    runne_application::provider::ProviderAuthorityIssueRequest {
        provider_id,
        principal_id: principal_id.into(),
        conversation_id: started.conversation_id,
        taskrun_id: started.taskrun_id,
        execution_attempt_id: started.attempt_id,
        prepared: runne_provider::PreparedProviderRecord {
            call_id: call.call_id(),
            call_digest_version: prepared.request_ref().digest_version(),
            prepared_digest: *prepared.request_ref().as_bytes(),
            render_digest: *prepared.render_digest(),
            profile_digest: [2; 32],
        },
        pricing_revision_digest: [3; 32],
        requested_input_tokens: 512,
        requested_output_tokens: 1_024,
        max_cost_micros: 50_000,
        currency: "USD".into(),
        provider_idempotency_key: "no-admission-after-cancel".into(),
    }
}

pub(super) fn assert_no_provider_effects(
    database: &Database,
    taskrun_id: runne_domain::id::TaskRunId,
    attempt_id: runne_domain::id::AttemptId,
) {
    let connection = database.connection();
    let counts: (i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM provider_execution_admissions WHERE taskrun_id=?1 AND execution_attempt_id=?2),
                    (SELECT COUNT(*) FROM provider_remote_request_intents WHERE taskrun_id=?1 AND taskrun_attempt_id=?2),
                    (SELECT COUNT(*) FROM provider_remote_terminal_artifacts WHERE taskrun_id=?1 AND taskrun_attempt_id=?2),
                    (SELECT COUNT(*) FROM provider_remote_terminal_applications WHERE taskrun_id=?1 AND taskrun_attempt_id=?2),
                    (SELECT COUNT(*) FROM taskrun_local_command_attempts WHERE taskrun_id=?1 AND (attempt_id IS NULL OR attempt_id=?2)),
                    (SELECT COUNT(*) FROM provider_execution_admissions WHERE provider_idempotency_key=?3),
                    (SELECT COUNT(*) FROM provider_dispatch_attempts WHERE provider_idempotency_key=?3),
                    (SELECT COUNT(*) FROM provider_budget_reservations WHERE provider_idempotency_key=?3),
                    (SELECT COUNT(*) FROM provider_accounting_settlements WHERE dispatch_attempt_id IN
                        (SELECT attempt_id FROM provider_dispatch_attempts WHERE provider_idempotency_key=?3)),
                    (SELECT COUNT(*) FROM provider_stream_journal WHERE dispatch_attempt_id IN
                        (SELECT attempt_id FROM provider_dispatch_attempts WHERE provider_idempotency_key=?3)),
                    (SELECT COUNT(*) FROM provider_terminal_outbox WHERE dispatch_attempt_id IN
                        (SELECT attempt_id FROM provider_dispatch_attempts WHERE provider_idempotency_key=?3)),
                    (SELECT COUNT(*) FROM provider_encryption_nonces WHERE dispatch_attempt_id IN
                        (SELECT attempt_id FROM provider_dispatch_attempts WHERE provider_idempotency_key=?3))",
            rusqlite::params![taskrun_id.as_bytes(), attempt_id.as_bytes(), "no-admission-after-cancel"],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?, row.get(10)?, row.get(11)?)),
        )
        .unwrap();
    assert_eq!(counts, (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
}

pub(super) fn assert_no_assistant_output(
    store: &impl runne_application::ports::ConversationRepository,
    conversation_id: runne_domain::id::ConversationId,
) {
    let conversation = store.load_conversation(conversation_id).unwrap();
    assert!(!conversation.events.iter().any(|event| matches!(
        event.payload(),
        runne_domain::conversation::ConversationEvent::AssistantMessageAppended { .. }
    )));
}
