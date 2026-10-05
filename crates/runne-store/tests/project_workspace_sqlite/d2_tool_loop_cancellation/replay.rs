use runne_application::{
    commands::{
        CancelTaskRunInput, CommandOutcome, ConversationTextCompletion, FinishConversationTextInput,
    },
    conversation_text_service::{ConversationTextCommandService, ConversationTextService},
    ports::{
        ConversationRepository, ConversationTextRepository, D2ToolLoopCancellationEvidence,
        EventStore, TextGenerationPhase, TextGenerationReceiptLookup,
    },
};
use runne_domain::{
    conversation::{Conversation, ConversationEvent, GenerationFailureReason},
    task_run::{TaskRun, TaskRunState},
};

#[test]
fn d2_pre_admission_cancel_projection_replays_after_two_validated_reopens() {
    let fixture = super::setup::prepare("d2-cancel-replay");
    let store = fixture.database.store.clone();
    let connection = fixture.database.connection();
    let admissions: i64 = connection
        .query_row(
            "SELECT count(*) FROM provider_execution_admissions WHERE taskrun_id=?1",
            [fixture.taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    let invocations: i64 = connection
        .query_row(
            "SELECT count(*) FROM taskrun_tool_invocations WHERE taskrun_id=?1",
            [fixture.taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!((admissions, invocations), (0, 0));
    drop(connection);
    let task_runs = super::super::taskrun_tool_invocation_positive::loop_task_runs_for_authority(
        &store,
        fixture.runtime_authority.clone(),
    );
    let before_cancel = store
        .load_task_run(fixture.taskrun_id)
        .unwrap()
        .current_version;
    let cancellation = task_runs
        .cancel_task_run(
            &super::super::support::task_context(0xfc, "d2-cancel-command"),
            CancelTaskRunInput {
                taskrun_id: fixture.taskrun_id,
                expected_version: before_cancel,
            },
        )
        .unwrap();
    let CommandOutcome::TaskRunCancellationRequested { new_version, .. } = cancellation else {
        panic!("D2 cancellation request expected")
    };
    let evidence = D2ToolLoopCancellationEvidence {
        node_id: *uuid::Uuid::parse_str(&fixture.assignment.node_id.0)
            .unwrap()
            .as_bytes(),
        node_epoch: fixture.assignment.node_epoch,
        fence: fixture.assignment.fence.0,
        cancellation_taskrun_version: new_version,
    };
    let connection = fixture.database.connection();
    let assignment_rows = connection
        .query_row(
            "SELECT c.new_version,c.node_id,c.node_epoch,c.fence,o.state,b.node_id,b.node_epoch,b.fence,b.policy_revision FROM taskrun_claim_receipts c JOIN taskrun_assignment_occupations o USING(taskrun_id,fence,attempt_id,node_id,node_epoch) JOIN taskrun_tool_budgets b USING(taskrun_id,attempt_id,fence,node_epoch) WHERE c.taskrun_id=?1 AND c.attempt_id=?2",
            rusqlite::params![fixture.taskrun_id.as_bytes(), fixture.assignment.attempt_id.as_bytes()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?, row.get::<_, String>(4)?, row.get::<_, String>(5)?, row.get::<_, i64>(6)?, row.get::<_, i64>(7)?, row.get::<_, String>(8)?)),
        )
        .unwrap();
    assert_eq!(assignment_rows.0, fixture.started.taskrun_version as i64);
    assert_eq!(assignment_rows.1, evidence.node_id);
    assert_eq!(assignment_rows.2, evidence.node_epoch as i64);
    assert_eq!(assignment_rows.3, evidence.fence as i64);
    assert_eq!(assignment_rows.4, "active");
    assert_eq!(assignment_rows.5, fixture.assignment.node_id.0);
    assert_eq!(assignment_rows.6, evidence.node_epoch as i64);
    assert_eq!(assignment_rows.7, evidence.fence as i64);
    assert_eq!(assignment_rows.8, "d2-safe-tool-loop-budget-v1");
    let current_assignment: (Vec<u8>, Vec<u8>, i64, i64) = connection
        .query_row(
            "SELECT attempt_id,node_id,node_epoch,fence FROM taskrun_assignments WHERE taskrun_id=?1",
            [fixture.taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        current_assignment.0,
        fixture.assignment.attempt_id.as_bytes()
    );
    assert_eq!(current_assignment.1, evidence.node_id);
    assert_eq!(current_assignment.2, evidence.node_epoch as i64);
    assert_eq!(current_assignment.3, evidence.fence as i64);
    let cancellation_assignment_valid: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_claim_receipts c
             JOIN taskrun_assignment_occupations o ON o.taskrun_id=c.taskrun_id AND o.fence=c.fence
                AND o.attempt_id=c.attempt_id AND o.node_id=c.node_id AND o.node_epoch=c.node_epoch
             JOIN taskrun_assignments a ON a.taskrun_id=c.taskrun_id AND a.fence=c.fence
                AND a.attempt_id=c.attempt_id AND a.node_id=c.node_id AND a.node_epoch=c.node_epoch
             JOIN taskrun_tool_budgets b ON b.taskrun_id=c.taskrun_id AND b.attempt_id=c.attempt_id
                AND b.fence=c.fence AND b.node_epoch=c.node_epoch
             WHERE c.taskrun_id=?1 AND c.attempt_id=?2 AND c.fence=?3 AND c.node_id=?4
               AND c.node_epoch=?5 AND c.new_version=?6 AND o.state='active'
               AND b.node_id=?7 AND b.policy_revision='d2-safe-tool-loop-budget-v1')",
            rusqlite::params![
                fixture.taskrun_id.as_bytes(),
                fixture.assignment.attempt_id.as_bytes(),
                evidence.fence as i64,
                evidence.node_id.as_slice(),
                evidence.node_epoch as i64,
                fixture.started.taskrun_version as i64,
                fixture.assignment.node_id.0,
            ],
            |row| row.get(0),
        )
        .unwrap();
    assert!(cancellation_assignment_valid);
    let text = ConversationTextService::new(
        store.clone(),
        store.clone(),
        fixture.runtime_authority.clone(),
        super::super::support::guard(),
    );
    let input = FinishConversationTextInput {
        original: fixture.original.clone(),
        started: fixture.started.clone(),
        completion: ConversationTextCompletion::D2ToolLoopCancellation { evidence },
    };
    let rejected = text
        .finish_text(&fixture.generation_context, input.clone())
        .unwrap();
    assert_eq!(rejected.phase, TextGenerationPhase::Rejected);
    assert_eq!(rejected.taskrun_version, new_version + 1);
    assert!(
        text.finish_text(&fixture.generation_context, input.clone())
            .is_ok()
    );
    assert_eq!(
        store
            .load_task_run(fixture.taskrun_id)
            .unwrap()
            .current_version,
        new_version + 1
    );
    for invalid in [
        D2ToolLoopCancellationEvidence {
            node_id: [0x91; 16],
            ..evidence
        },
        D2ToolLoopCancellationEvidence {
            node_epoch: evidence.node_epoch + 1,
            ..evidence
        },
        D2ToolLoopCancellationEvidence {
            fence: evidence.fence + 1,
            ..evidence
        },
        D2ToolLoopCancellationEvidence {
            cancellation_taskrun_version: evidence.cancellation_taskrun_version - 1,
            ..evidence
        },
    ] {
        assert!(
            store
                .validate_d2_tool_loop_cancellation_receipt(&rejected, invalid)
                .is_err()
        );
    }

    let conversation_stream = store.load_conversation(fixture.conversation_id).unwrap();
    let _conversation = Conversation::replay(&conversation_stream.events).unwrap();
    assert_eq!(
        conversation_stream.current_version,
        rejected.conversation_version
    );
    assert!(matches!(
        conversation_stream
            .events
            .last()
            .map(|event| event.payload()),
        Some(ConversationEvent::GenerationFailed {
            reason: GenerationFailureReason::Cancelled,
            ..
        })
    ));
    let taskrun_stream = store.load_task_run(fixture.taskrun_id).unwrap();
    let taskrun = TaskRun::replay(&taskrun_stream.events).unwrap();
    assert_eq!(taskrun.state(), TaskRunState::Cancelled);
    assert_eq!(
        taskrun_stream.events.last().map(|event| event.payload()),
        Some(&runne_domain::task_run::TaskRunEvent::CancellationCompleted)
    );

    drop(text);
    drop(task_runs);
    drop(store);
    let reopened = crate::validated_reopen::reopen_store(
        fixture.database.file.path(),
        fixture.database.identity,
        fixture.runtime_authority.clone(),
        super::super::support::guard(),
    )
    .unwrap();
    let reopened_text = ConversationTextService::new(
        reopened.clone(),
        reopened.clone(),
        fixture.runtime_authority.clone(),
        super::super::support::guard(),
    );
    assert_eq!(
        reopened_text
            .finish_text(&fixture.generation_context, input.clone())
            .unwrap(),
        rejected
    );
    drop(reopened_text);
    let lookup = reopened.lookup_text_generation_receipt(
        fixture.generation_context.command_id,
        &fixture.generation_context.idempotency_key,
        &fixture.scope,
        &fixture.fingerprint,
    );
    assert!(
        matches!(lookup, Ok(TextGenerationReceiptLookup::Duplicate { stored_result }) if stored_result == rejected)
    );
    let reopened_again = crate::validated_reopen::reopen_store(
        fixture.database.file.path(),
        fixture.database.identity,
        fixture.runtime_authority.clone(),
        super::super::support::guard(),
    )
    .unwrap();
    let reopened_again_text = ConversationTextService::new(
        reopened_again.clone(),
        reopened_again.clone(),
        fixture.runtime_authority.clone(),
        super::super::support::guard(),
    );
    assert_eq!(
        reopened_again_text
            .finish_text(&fixture.generation_context, input)
            .unwrap(),
        rejected
    );
    assert!(matches!(
        reopened_again.lookup_text_generation_receipt(
            fixture.generation_context.command_id,
            &fixture.generation_context.idempotency_key,
            &fixture.scope,
            &fixture.fingerprint,
        ),
        Ok(TextGenerationReceiptLookup::Duplicate { stored_result }) if stored_result == rejected
    ));
    assert_eq!(
        reopened_again
            .load_task_run(fixture.taskrun_id)
            .unwrap()
            .current_version,
        rejected.taskrun_version
    );
    assert_eq!(
        reopened_again
            .load_conversation(fixture.conversation_id)
            .unwrap()
            .current_version,
        rejected.conversation_version
    );
}
