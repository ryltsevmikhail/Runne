use super::cancellation_support::{pending_terminal_snapshot, request_public_cancellation};
use super::*;
use runne_application::ports::{ConversationRepository, EventStore};
use runne_application::ports::{ExecutionNodeId, RuntimeAuthorityId};
use runne_application::service::TaskRunService;
use runne_domain::task_run::{TaskRun, TaskRunState};
use runne_runtime::provider_execution::RuntimeProviderExecution;
use runne_runtime::provider_redaction::{
    ProhibitedContentCredentialMatcher, ProviderEventRedactionBoundary,
};
use runne_runtime::taskrun_auto_worker::AutomaticTaskRunService;
use std::sync::{Arc, atomic::AtomicU64};

#[tokio::test(flavor = "current_thread")]
async fn foreground_terminal_apply_defers_if_cancel_wins_after_running_check() {
    let scenario = setup::prepare_failure_scenario().await;
    terminal_success::seal_success_only(&scenario).await;
    assert!(
        crate::canonical_provider::foreground_cancellation_result(
            &scenario.harness.store,
            scenario.taskrun_id,
            scenario.conversation_id,
            scenario.claim.attempt_id,
            scenario.begin_context.command_id,
            &scenario.begin_context.idempotency_key,
        )
        .unwrap()
        .is_none(),
        "foreground observed Running before the cancellation race"
    );
    request_public_cancellation(&scenario);

    let service = &scenario.service;
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
    assert!(
        !runtime
            .apply_terminal_output_for_attempt(
                scenario.provider_claim.attempt_id,
                &scenario.harness.terminal_application(),
            )
            .unwrap()
    );
    assert_eq!(
        TaskRun::replay(
            &scenario
                .harness
                .store
                .load_task_run(scenario.taskrun_id)
                .unwrap()
                .events
        )
        .unwrap()
        .state(),
        TaskRunState::Cancelling
    );
    assert_eq!(pending_terminal_snapshot(&scenario.harness).state, 1);
    assert!(
        !scenario
            .harness
            .store
            .load_conversation(scenario.conversation_id)
            .unwrap()
            .events
            .iter()
            .any(|event| matches!(
                event.payload(),
                runne_domain::conversation::ConversationEvent::AssistantMessageAppended { .. }
                    | runne_domain::conversation::ConversationEvent::GenerationFailed {
                        reason: runne_domain::conversation::GenerationFailureReason::Cancelled,
                        ..
                    }
            ))
    );

    let taskruns = Arc::new(TaskRunService::new(
        scenario.harness.store.clone(),
        scenario.harness.store.clone(),
        scenario.harness.store.clone(),
        RuntimeAuthorityId(hex::encode(service.runtime_authority_id)),
    ));
    let generation = scenario.harness.generation();
    let worker = crate::application::exec_taskrun_worker::DaemonAutomaticTaskRuns::new(
        scenario.harness.store.clone(),
        taskruns,
        scenario.harness.text_service(),
        Some(service.clone()),
        ExecutionNodeId(uuid::Uuid::from_bytes(service.runtime_authority_id).to_string()),
        generation,
        Arc::new(AtomicU64::new(generation)),
    );
    AutomaticTaskRunService::complete_queued_cancellation(
        &worker,
        scenario.taskrun_id,
        scenario.claim.new_version + 1,
    )
    .await
    .unwrap();
    assert_eq!(
        TaskRun::replay(
            &scenario
                .harness
                .store
                .load_task_run(scenario.taskrun_id)
                .unwrap()
                .events
        )
        .unwrap()
        .state(),
        TaskRunState::Cancelled
    );
    assert_eq!(pending_terminal_snapshot(&scenario.harness).state, 2);
    let conversation = scenario
        .harness
        .store
        .load_conversation(scenario.conversation_id)
        .unwrap();
    assert!(conversation.events.iter().any(|event| matches!(
        event.payload(),
        runne_domain::conversation::ConversationEvent::GenerationFailed {
            reason: runne_domain::conversation::GenerationFailureReason::Cancelled,
            ..
        }
    )));
    assert!(!conversation.events.iter().any(|event| matches!(
        event.payload(),
        runne_domain::conversation::ConversationEvent::AssistantMessageAppended { .. }
    )));
}
