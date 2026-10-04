use crate::application::exec_taskrun_worker::DaemonAutomaticTaskRuns;
use runne_application::commands::{CancelTaskRunInput, CommandOutcome};
use runne_application::ports::{ConversationTextRepository, ExecutionNodeId, RuntimeAuthorityId};
use runne_application::service::TaskRunService;
use runne_runtime::taskrun_auto_worker::AutomaticTaskRunService;
use std::sync::{Arc, atomic::AtomicU64};
mod support;
use support::{
    Mutation, assert_cancelled_state, assert_revoked_authority_is_rejected, cancellation_state,
    direct_cancellation_payload, verify_replay_after_corruption_and_advance,
};

#[tokio::test(flavor = "current_thread")]
async fn live_scanner_closes_state2_rejection_without_provider_or_accounting() {
    run_live_case(false, false, false, false).await;
    run_live_case(true, false, false, false).await;
    run_live_case(false, true, false, false).await;
    run_live_case(false, false, true, false).await;
    run_live_case(false, false, false, true).await;
    run_live_case(true, false, false, true).await;
}

async fn run_live_case(
    bind_before_reject: bool,
    boot_recovery: bool,
    cancel_before_rejection: bool,
    direct_commit: bool,
) {
    let scenario = super::setup::prepare_failure_scenario().await;
    assert!(super::terminal_success::seal_success_and_try_foreground(&scenario).await);
    let harness = scenario.harness;
    let service = scenario.service;
    let conversation_id = scenario.conversation_id;
    let workspace_id = scenario.workspace_id;
    let rejected = super::rejection::dispatch_rejected_generation(
        &harness,
        &service,
        conversation_id,
        workspace_id,
        bind_before_reject,
        cancel_before_rejection,
    )
    .await;
    let tasks = Arc::new(TaskRunService::new(
        harness.store.clone(),
        harness.store.clone(),
        harness.store.clone(),
        RuntimeAuthorityId(hex::encode(service.runtime_authority_id)),
    ));
    let cancel = crate::canonical_provider::composition::tests::command_context(
        "018f2e3a-7000-7000-8000-000000000150",
        "pre-effect-cancel",
    );
    let new_version = match rejected.cancelled_before_rejection {
        Some(version) => version,
        None => {
            let outcome = tasks
                .cancel_task_run(
                    &cancel,
                    CancelTaskRunInput {
                        taskrun_id: rejected.taskrun_id,
                        expected_version: rejected.claim_version,
                    },
                )
                .unwrap();
            let CommandOutcome::TaskRunCancellationRequested { new_version, .. } = outcome else {
                panic!("cancellation did not win the TaskRun version")
            };
            new_version
        }
    };
    let started = harness
        .store
        .load_text_generation_receipt_by_command(
            rejected.begin_context.command_id,
            &rejected.begin_context.idempotency_key,
        )
        .unwrap();
    let control_payload = direct_cancellation_payload(
        &harness.store,
        &rejected.begin_context,
        &started,
        new_version,
        service.runtime_authority_id,
        None,
    );
    let replay_evidence = control_payload.evidence;
    for mutation in [
        Mutation::AssistantId,
        Mutation::Workspace,
        Mutation::Authority,
        Mutation::Fingerprint,
        Mutation::Principal,
        Mutation::DispatchId,
        Mutation::CancellationVersion,
    ] {
        let payload = direct_cancellation_payload(
            &harness.store,
            &rejected.begin_context,
            &started,
            new_version,
            service.runtime_authority_id,
            Some(mutation),
        );
        let before = cancellation_state(&harness, rejected.taskrun_id, conversation_id);
        let receipt_before = harness
            .store
            .load_text_generation_receipt_by_command(
                rejected.begin_context.command_id,
                &rejected.begin_context.idempotency_key,
            )
            .unwrap();
        assert!(
            harness
                .store
                .reject_text_generation_after_pre_effect_cancellation(payload)
                .is_err()
        );
        assert_eq!(
            cancellation_state(&harness, rejected.taskrun_id, conversation_id),
            before
        );
        assert_eq!(
            harness
                .store
                .load_text_generation_receipt_by_command(
                    rejected.begin_context.command_id,
                    &rejected.begin_context.idempotency_key,
                )
                .unwrap(),
            receipt_before
        );
    }
    if direct_commit {
        assert_revoked_authority_is_rejected(
            &harness,
            rejected.taskrun_id,
            conversation_id,
            &rejected.begin_context,
            &control_payload,
        );
        if bind_before_reject {
            support::assert_binding_mismatch_is_rejected(
                &harness,
                rejected.taskrun_id,
                conversation_id,
                &rejected.begin_context,
                &control_payload,
            );
        } else {
            support::assert_unexpected_intent_is_rejected(
                &harness,
                rejected.taskrun_id,
                conversation_id,
                &rejected.begin_context,
                &control_payload,
            );
        }
        support::assert_uncertain_dispatch_is_rejected(
            &harness,
            rejected.taskrun_id,
            conversation_id,
            &rejected.begin_context,
            &control_payload,
        );
        assert!(matches!(
            harness
                .store
                .reject_text_generation_after_pre_effect_cancellation(control_payload.clone())
                .unwrap(),
            runne_application::ports::TextGenerationCommitResult::Committed { .. }
        ));
    }
    let generation = harness.generation();
    if !direct_commit && boot_recovery {
        #[cfg(all(test, feature = "desktop-protected", target_os = "linux"))]
        crate::application::exec_taskrun_recovery::provider_only_taskrun_service_for_test(
            harness.store.clone(),
            tasks,
            service.conversation_service.clone(),
            None,
            service.runtime_authority_id,
            generation,
            Arc::new(AtomicU64::new(generation)),
        )
        .unwrap();
        #[cfg(not(all(test, feature = "desktop-protected", target_os = "linux")))]
        crate::application::exec_taskrun_recovery::automatic_taskrun_service(
            harness.store.clone(),
            tasks,
            service.conversation_service.clone(),
            None,
            service.runtime_authority_id,
            generation,
            Arc::new(AtomicU64::new(generation)),
        )
        .unwrap();
    } else if !direct_commit {
        let worker = DaemonAutomaticTaskRuns::new(
            harness.store.clone(),
            tasks,
            service.conversation_service.clone(),
            None,
            ExecutionNodeId(uuid::Uuid::from_bytes(service.runtime_authority_id).to_string()),
            generation,
            Arc::new(AtomicU64::new(generation)),
        );
        AutomaticTaskRunService::complete_queued_cancellation(
            &worker,
            rejected.taskrun_id,
            new_version,
        )
        .await
        .unwrap();
    }
    assert!(matches!(
        harness
            .store
            .reject_text_generation_after_pre_effect_cancellation(control_payload)
            .unwrap(),
        runne_application::ports::TextGenerationCommitResult::Duplicate { .. }
    ));

    let replay_input = runne_application::commands::BeginClaimedConversationTextInput {
        original: runne_application::commands::BeginConversationTextInput {
            conversation_id,
            expected_version: started.conversation_version - 1,
            text: runne_domain::message::MessageText::new("rejected prompt").unwrap(),
        },
        taskrun_id: rejected.taskrun_id,
        attempt_id: rejected.assignment.attempt_id,
        taskrun_version: rejected.claim_version,
        workspace_id: rejected.workspace_id,
        assignment: rejected.assignment.clone(),
    };
    let replay = service
        .conversation_service
        .begin_claimed_text(&rejected.begin_context, replay_input.clone())
        .unwrap();
    assert_eq!(
        replay.phase,
        runne_application::ports::TextGenerationPhase::Rejected
    );
    assert_eq!(replay.taskrun_version, new_version + 1);

    verify_replay_after_corruption_and_advance(
        &harness,
        support::ReplayPlan {
            text_service: service.conversation_service.as_ref(),
            context: &rejected.begin_context,
            replay_input,
            started,
            evidence: replay_evidence,
            conversation_id,
            taskrun_id: rejected.taskrun_id,
            node_epoch: rejected.assignment.node_epoch,
        },
    );

    assert_cancelled_state(
        &harness,
        rejected.taskrun_id,
        conversation_id,
        &rejected.begin_context,
        new_version,
    );
}
