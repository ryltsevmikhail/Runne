use super::cancellation_support::{pending_terminal_snapshot, request_public_cancellation};
use super::*;
use runne_application::ports::{ConversationRepository, EventStore};
use runne_domain::task_run::{TaskRun, TaskRunState};
use runne_runtime::provider_execution::{
    ProviderTerminalOutboxApplication, RecoveredProviderTerminalCancellation,
    RuntimeProviderExecution,
};
use runne_runtime::provider_redaction::{
    ProhibitedContentCredentialMatcher, ProviderEventRedactionBoundary,
};

#[tokio::test(flavor = "current_thread")]
async fn replay_after_cancel_receipt_commit_before_outbox_ack_is_read_only() {
    let scenario = setup::prepare_failure_scenario().await;
    request_public_cancellation(&scenario);
    assert!(!terminal_success::seal_success_and_try_foreground(&scenario).await);
    let PreparedFailureScenario {
        harness,
        service,
        taskrun_id,
        ..
    } = scenario;
    let matcher = ProhibitedContentCredentialMatcher::new(service.prohibited_content.as_ref());
    let redaction = ProviderEventRedactionBoundary::new(
        service.tail_store.as_ref(),
        service.scanner_store.as_ref(),
        &matcher,
    );
    let runtime = RuntimeProviderExecution::new(
        service.keyring.as_ref(),
        service.execution_store.as_ref(),
        service.profile.as_ref(),
        service.prohibited_content.as_ref(),
        &redaction,
    );
    runtime
        .preflight_existing_active_key(service.runtime_authority_id, service.database_generation)
        .unwrap();
    let mut pending = runtime.recover_pending_terminal_outputs().unwrap();
    assert_eq!(pending.len(), 1);
    let terminal = pending.pop().unwrap();
    let recovered = runne_runtime::provider_execution::ProviderTerminalConversationResolver::resolve_provider_terminal_conversation(
        &harness.store, terminal.record(),
    ).unwrap_or_else(|error| panic!("terminal resolver: {error:?}"));
    assert_eq!(
        recovered.started,
        harness
            .store
            .load_text_generation_receipt_by_command(
                recovered.context.command_id,
                &recovered.context.idempotency_key,
            )
            .unwrap()
    );
    let conversation_id = recovered.started.conversation_id;
    let Some(RecoveredProviderTerminalCancellation::StreamJournal(cancellation_evidence)) =
        recovered.terminal_cancellation
    else {
        panic!("expected the foreground stream cancellation witness");
    };
    let receipt = harness.text_service().finish_text(
        &recovered.context,
        runne_application::commands::FinishConversationTextInput {
            original: recovered.original,
            started: recovered.started,
            completion: runne_application::commands::ConversationTextCompletion::TerminalSettledCancellation {
                evidence: cancellation_evidence,
            },
        },
    ).unwrap_or_else(|error| panic!("terminal finish: {error:?}"));
    assert_eq!(
        receipt.phase,
        runne_application::ports::TextGenerationPhase::Rejected
    );
    assert_eq!(pending_terminal_snapshot(&harness).state, 1);
    assert_eq!(
        TaskRun::replay(&harness.store.load_task_run(taskrun_id).unwrap().events)
            .unwrap()
            .state(),
        TaskRunState::Cancelled
    );
    let old_fence = harness
        .query_connection()
        .query_row(
            "SELECT fencing_token FROM conversation_writer_leases WHERE conversation_id=?1",
            [conversation_id.as_bytes()],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    assert_eq!(old_fence, 1);
    harness
        .store
        .take_control_conversation_writer_lease(
            conversation_id.as_bytes(),
            "later-principal",
            old_fence as u64,
        )
        .unwrap();
    let conversation_version = harness
        .store
        .load_conversation(conversation_id)
        .unwrap()
        .current_version;
    let replay = runtime.recover_pending_terminal_outputs().unwrap();
    assert_eq!(replay.len(), 1);
    let replay_result = runne_runtime::provider_execution::ProviderTerminalConversationResolver::resolve_provider_terminal_conversation(
        &harness.store, replay[0].record(),
    );
    assert!(
        replay_result.is_ok(),
        "post-commit resolver: {:?}",
        replay_result.err()
    );
    let replay_receipt = harness
        .terminal_application()
        .complete_provider_terminal(replay[0].record(), replay[0].output());
    assert!(
        replay_receipt.is_ok(),
        "post-commit terminal apply: {:?}",
        replay_receipt.err()
    );
    assert_eq!(
        harness
            .store
            .load_conversation(conversation_id)
            .unwrap()
            .current_version,
        conversation_version,
        "old outbox replay is a receipt read after writer takeover"
    );
    drop(service);

    let reopened = harness
        .try_compose_openai_provider_at_generation(harness.generation())
        .await
        .unwrap();
    assert_eq!(pending_terminal_snapshot(&harness).state, 2);
    let after_ack = snapshot(&harness);
    reopened.recover_pending().await.unwrap();
    assert_eq!(snapshot(&harness), after_ack);
}
