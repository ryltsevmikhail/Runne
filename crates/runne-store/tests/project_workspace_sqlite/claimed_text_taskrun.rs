use runne_application::commands::{
    BeginClaimedConversationTextInput, BeginConversationTextInput, CommandOutcome,
    ConversationTextCompletion, FinishConversationTextInput,
};
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use runne_application::ports::{
    EventStore, ExecutionNodeId, TaskRunAssignmentIdentity, TaskRunClaimResult,
};
use runne_domain::id::{ConversationId, WorkspaceId};
use runne_domain::message::MessageText;

use super::{claim::node_registration, submit_fence::submit_task_run, support::*};

#[test]
fn claimed_text_finish_retires_exact_assignment_atomically() {
    let database = Database::new("claimed-text-terminal-settlement");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let submitted = submit_task_run(&database, 0x41, "claimed-text-finish");
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = submitted else {
        panic!()
    };
    let conversation_id = ConversationId::from_bytes(command(0x51).into_bytes());
    let workspace_id = WorkspaceId::from_bytes(WORKSPACE);
    let (node, node_epoch) = node_registration(&database);
    let claim = database
        .task_runs()
        .claim_task_run(
            &task_context(0x42, "claim-for-text-finish"),
            runne_application::service::ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: ExecutionNodeId(node),
                node_epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 20_000,
            },
            &database.store,
        )
        .unwrap();
    let TaskRunClaimResult::Committed(claim) = claim else {
        panic!("claim commits")
    };
    let assignment = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: claim.attempt_id,
        node_id: claim.node_id.clone(),
        node_epoch: claim.node_epoch,
        fence: claim.fence,
    };
    let service = ConversationTextService::new(
        database.store.clone(),
        database.store.clone(),
        authority(),
        guard(),
    );
    let original = BeginConversationTextInput {
        conversation_id,
        expected_version: 1,
        text: MessageText::new("test prompt").unwrap(),
    };
    let generation_context = task_context(0x43, "begin-claimed-text");
    let started = service
        .begin_claimed_text(
            &generation_context,
            BeginClaimedConversationTextInput {
                original: original.clone(),
                taskrun_id,
                attempt_id: claim.attempt_id,
                taskrun_version: claim.new_version,
                workspace_id,
                assignment: assignment.clone(),
            },
        )
        .unwrap();
    assert_eq!(started.taskrun_id, taskrun_id);
    assert_eq!(started.attempt_id, claim.attempt_id);
    assert_eq!(
        database
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM aggregate_streams WHERE aggregate_type=1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );

    let finished = service.finish_text(
        &generation_context,
        FinishConversationTextInput {
            original, started, completion: ConversationTextCompletion::Rejected {
                reason: runne_domain::conversation::GenerationFailureReason::ProviderExecutionRejected,
            },
        },
    ).unwrap();
    assert_eq!(
        finished.phase,
        runne_application::ports::TextGenerationPhase::Rejected
    );
    let replayed = service
        .begin_claimed_text(
            &generation_context,
            BeginClaimedConversationTextInput {
                original: BeginConversationTextInput {
                    conversation_id,
                    expected_version: 1,
                    text: MessageText::new("test prompt").unwrap(),
                },
                taskrun_id,
                attempt_id: claim.attempt_id,
                taskrun_version: claim.new_version,
                workspace_id,
                assignment: assignment.clone(),
            },
        )
        .unwrap();
    assert_eq!(replayed, finished);
    let mut substituted = assignment.clone();
    substituted.fence.0 += 1;
    assert!(
        service
            .begin_claimed_text(
                &generation_context,
                BeginClaimedConversationTextInput {
                    original: BeginConversationTextInput {
                        conversation_id,
                        expected_version: 1,
                        text: MessageText::new("test prompt").unwrap(),
                    },
                    taskrun_id,
                    attempt_id: claim.attempt_id,
                    taskrun_version: claim.new_version,
                    workspace_id,
                    assignment: substituted,
                },
            )
            .is_err()
    );
    let connection = database.connection();
    let released: (String, Vec<u8>) = connection.query_row(
        "SELECT state,release_event_id FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2",
        rusqlite::params![taskrun_id.as_bytes(), claim.fence.0 as i64],
        |row| Ok((row.get(0)?,row.get(1)?)),
    ).unwrap();
    assert_eq!(released.0, "released");
    assert_eq!(
        released.1.as_slice(),
        database
            .store
            .load_task_run(taskrun_id)
            .unwrap()
            .last_event_id
            .unwrap()
            .as_bytes()
    );
    let proof_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1 AND fence=?2",
        rusqlite::params![taskrun_id.as_bytes(), claim.fence.0 as i64], |row| row.get(0),
    ).unwrap();
    assert_eq!(proof_count, 1);
    let reopened = crate::validated_reopen::reopen_store(
        database.file.path(),
        database.identity,
        authority(),
        guard(),
    )
    .unwrap();
    assert_eq!(
        reopened.load_task_run(taskrun_id).unwrap().current_version,
        claim.new_version + 1
    );
}
