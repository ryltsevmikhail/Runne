use super::*;
use runne_application::ports::ConversationRepository;
use runne_domain::task_run::{TaskRun, TaskRunState};

use super::cancellation_support::{pending_terminal_snapshot, request_public_cancellation};

#[tokio::test(flavor = "current_thread")]
async fn valid_pending_cancel_suppresses_success_and_completes_terminal_outbox_on_boot() {
    let scenario = setup::prepare_failure_scenario().await;
    request_public_cancellation(&scenario);
    assert!(!terminal_success::seal_success_and_try_foreground(&scenario).await);
    assert!(
        crate::canonical_provider::foreground_cancellation_result(
            &scenario.harness.store,
            scenario.taskrun_id,
            scenario.conversation_id,
            scenario.claim.attempt_id,
            scenario.begin_context.command_id,
            &scenario.begin_context.idempotency_key,
        )
        .is_err(),
        "the production foreground post-commit branch leaves settlement to the scanner"
    );
    let PreparedFailureScenario {
        harness,
        service,
        taskrun_id,
        conversation_id,
        begin_context,
        ..
    } = scenario;
    let accounting_before = harness.query_connection().query_row(
        "SELECT settlement_digest,charge_micros,input_tokens,output_tokens FROM provider_accounting_settlements",
        [], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?)),
    ).unwrap();
    drop(service);

    let reopened = harness
        .try_compose_openai_provider_at_generation(harness.generation())
        .await
        .expect("valid cancellation must not abort boot");
    assert_eq!(
        TaskRun::replay(&harness.store.load_task_run(taskrun_id).unwrap().events)
            .unwrap()
            .state(),
        TaskRunState::Cancelled,
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
        runne_application::ports::TextGenerationPhase::Rejected
    );
    assert!(
        !harness
            .store
            .load_conversation(conversation_id)
            .unwrap()
            .events
            .iter()
            .any(|event| matches!(
                event.payload(),
                runne_domain::conversation::ConversationEvent::AssistantMessageAppended { .. }
            ))
    );
    assert_eq!(pending_terminal_snapshot(&harness).state, 2);
    assert_eq!(harness.query_connection().query_row(
        "SELECT settlement_digest,charge_micros,input_tokens,output_tokens FROM provider_accounting_settlements",
        [], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?)),
    ).unwrap(), accounting_before);
    assert_eq!(
        harness
            .query_connection()
            .query_row(
                "SELECT disposition FROM provider_terminal_dispositions",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    let after_boot = snapshot(&harness);
    reopened.recover_pending().await.unwrap();
    reopened.recover_pending().await.unwrap();
    assert_eq!(snapshot(&harness), after_boot);
    drop(reopened);
    let reopened_again = harness
        .try_compose_openai_provider_at_generation(harness.generation())
        .await
        .expect("repeated recovery must converge idempotently");
    assert_unchanged_except(
        &after_boot,
        &snapshot(&harness),
        &["provider_runtime_authority_state"],
    );
    assert_eq!(pending_terminal_snapshot(&harness).state, 2);
    drop(reopened_again);
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_unmarked_terminal_under_pending_cancel_defers_boot_without_mutation() {
    let scenario = setup::prepare_failure_scenario().await;
    request_public_cancellation(&scenario);
    assert!(!terminal_success::seal_success_and_try_foreground(&scenario).await);
    let PreparedFailureScenario {
        harness,
        service,
        taskrun_id,
        begin_context,
        ..
    } = scenario;
    drop(service);
    harness
        .writer_connection()
        .execute_batch(
            "DROP TRIGGER provider_terminal_dispositions_no_delete;
             DROP TRIGGER schema_v12_fence_provider_terminal_dispositions_delete;
             DELETE FROM provider_terminal_dispositions;
             CREATE TRIGGER provider_terminal_dispositions_no_delete
               BEFORE DELETE ON provider_terminal_dispositions
               BEGIN SELECT RAISE(ABORT,'Provider terminal disposition is append only'); END;
             CREATE TRIGGER \"schema_v12_fence_provider_terminal_dispositions_delete\"
               AFTER DELETE ON \"provider_terminal_dispositions\"
               BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1)
               ON CONFLICT(id) DO NOTHING; END;",
        )
        .unwrap();

    let reopened = harness
        .try_compose_openai_provider_at_generation(harness.generation())
        .await
        .expect("a v49 settlement without new disposition evidence remains deferred");
    let pending = snapshot(&harness);
    assert_eq!(pending_terminal_snapshot(&harness).state, 1);
    assert_eq!(
        TaskRun::replay(&harness.store.load_task_run(taskrun_id).unwrap().events)
            .unwrap()
            .state(),
        TaskRunState::Cancelling
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
    assert_eq!(
        harness
            .query_connection()
            .query_row(
                "SELECT COUNT(*) FROM provider_terminal_dispositions",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    reopened.recover_pending().await.unwrap();
    assert_eq!(snapshot(&harness), pending);
}
