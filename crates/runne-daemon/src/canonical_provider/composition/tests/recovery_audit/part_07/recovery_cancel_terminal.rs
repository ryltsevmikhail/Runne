use super::*;
use crate::application::exec_taskrun_worker::DaemonAutomaticTaskRuns;
use provider::FailureProvider;
use runne_application::ports::{
    ConversationRepository, EventStore, ExecutionNodeId, RuntimeAuthorityId,
};
use runne_application::service::TaskRunService;
use runne_domain::task_run::{TaskRun, TaskRunState};
use runne_provider::{ProviderTerminalDisposition, StreamCursor};
use runne_runtime::provider_execution::{ProviderEventJournalContext, RuntimeProviderExecution};
use runne_runtime::provider_redaction::{
    ProhibitedContentCredentialMatcher, ProviderEventRedactionBoundary,
};
use runne_runtime::taskrun_auto_worker::AutomaticTaskRunService;
use std::sync::{Arc, atomic::AtomicU64};

use super::cancellation_support::request_public_cancellation;

#[tokio::test(flavor = "current_thread")]
async fn ordinary_rejection_cannot_construct_cancelled_terminal_reason() {
    let scenario = setup::prepare_failure_scenario().await;
    let PreparedFailureScenario {
        harness,
        taskrun_id,
        conversation_id,
        begin_context,
        ..
    } = scenario;
    let started = harness
        .store
        .load_text_generation_receipt_by_command(
            begin_context.command_id,
            &begin_context.idempotency_key,
        )
        .unwrap();
    let result = harness.text_service().finish_text(
        &begin_context,
        runne_application::commands::FinishConversationTextInput {
            original: runne_application::commands::BeginConversationTextInput {
                conversation_id,
                expected_version: started.conversation_version - 1,
                text: runne_domain::message::MessageText::new("failure prompt").unwrap(),
            },
            started,
            completion: runne_application::commands::ConversationTextCompletion::Rejected {
                reason: runne_domain::conversation::GenerationFailureReason::Cancelled,
            },
        },
    );
    assert!(result.is_err());
    assert_eq!(
        TaskRun::replay(&harness.store.load_task_run(taskrun_id).unwrap().events)
            .unwrap()
            .state(),
        TaskRunState::Running
    );
    assert_eq!(
        harness
            .store
            .load_text_generation_receipt_by_command(
                begin_context.command_id,
                &begin_context.idempotency_key,
            )
            .unwrap()
            .phase,
        runne_application::ports::TextGenerationPhase::Started
    );
}

#[tokio::test(flavor = "current_thread")]
async fn exact_cancellation_scanner_closes_settled_remote_failure_without_relabeling_it() {
    for disposition in [
        ProviderTerminalDisposition::RemoteFailed,
        ProviderTerminalDisposition::RemoteIncomplete,
    ] {
        let scenario = setup::prepare_failure_scenario().await;
        request_public_cancellation(&scenario);
        let PreparedFailureScenario {
            harness,
            service,
            taskrun_id,
            conversation_id,
            claim,
            begin_context,
            provider_claim,
            record,
            stream,
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
            service.runtime_store.as_ref(),
            service.profile.as_ref(),
            service.prohibited_content.as_ref(),
            &redaction,
        );
        runtime
            .preflight_existing_active_key(
                service.runtime_authority_id,
                service.database_generation,
            )
            .unwrap();
        let context = ProviderEventJournalContext {
            attempt_id: provider_claim.attempt_id,
            fencing_token: provider_claim.fencing_token,
            call_digest_version: record.call_digest_version,
            profile_digest: record.profile_digest,
            runtime_generation: service.runtime_generation,
        };
        for sequence in 0..3 {
            runtime
                .next_and_commit(
                    &FailureProvider { disposition },
                    &stream,
                    StreamCursor::new(sequence),
                    &context,
                )
                .await
                .unwrap();
        }
        runtime.finalize_terminal_output(&context).unwrap();
        let cancellation_version = claim.new_version + 1;
        let taskruns = Arc::new(TaskRunService::new(
            harness.store.clone(),
            harness.store.clone(),
            harness.store.clone(),
            RuntimeAuthorityId(hex::encode(service.runtime_authority_id)),
        ));
        let worker = DaemonAutomaticTaskRuns::new(
            harness.store.clone(),
            taskruns,
            harness.text_service(),
            Some(service.clone()),
            ExecutionNodeId(uuid::Uuid::from_bytes(service.runtime_authority_id).to_string()),
            harness.generation(),
            Arc::new(AtomicU64::new(harness.generation())),
        );
        AutomaticTaskRunService::complete_queued_cancellation(
            &worker,
            taskrun_id,
            cancellation_version,
        )
        .await
        .unwrap();
        assert_eq!(
            TaskRun::replay(&harness.store.load_task_run(taskrun_id).unwrap().events)
                .unwrap()
                .state(),
            TaskRunState::Cancelled
        );
        let conversation = harness.store.load_conversation(conversation_id).unwrap();
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
        assert_eq!(
            harness
                .store
                .load_text_generation_receipt_by_command(
                    begin_context.command_id,
                    &begin_context.idempotency_key,
                )
                .unwrap()
                .phase,
            runne_application::ports::TextGenerationPhase::Rejected
        );
        assert_eq!(
            harness
                .query_connection()
                .query_row(
                    "SELECT disposition FROM provider_terminal_dispositions",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            if disposition == ProviderTerminalDisposition::RemoteFailed {
                2
            } else {
                3
            }
        );
    }
}
