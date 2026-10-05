#[test]
fn bad_d2_cancel_proof_leaves_started_receipt_nonterminal() {
    let fixture = super::setup::prepare("d2-cancel-bad-proof");
    let task_runs = super::super::taskrun_tool_invocation_positive::loop_task_runs_for_authority(
        &fixture.database.store,
        fixture.runtime_authority.clone(),
    );
    let expected_version = fixture
        .database
        .store
        .load_task_run(fixture.taskrun_id)
        .unwrap()
        .current_version;
    let cancellation = task_runs
        .cancel_task_run(
            &super::super::support::task_context(0xfd, "d2-bad-proof-cancel"),
            CancelTaskRunInput {
                taskrun_id: fixture.taskrun_id,
                expected_version,
            },
        )
        .unwrap();
    let CommandOutcome::TaskRunCancellationRequested { new_version, .. } = cancellation else {
        panic!("TaskRun cancellation request expected")
    };
    let wrong = D2ToolLoopCancellationEvidence {
        node_id: [0x91; 16],
        node_epoch: fixture.assignment.node_epoch,
        fence: fixture.assignment.fence.0,
        cancellation_taskrun_version: new_version,
    };
    let input = FinishConversationTextInput {
        original: fixture.original.clone(),
        started: fixture.started.clone(),
        completion: ConversationTextCompletion::D2ToolLoopCancellation { evidence: wrong },
    };
    let text = ConversationTextService::new(
        fixture.database.store.clone(),
        fixture.database.store.clone(),
        fixture.runtime_authority.clone(),
        super::super::support::guard(),
    );
    assert!(
        text.finish_text(&fixture.generation_context, input)
            .is_err()
    );
    assert_eq!(
        fixture
            .database
            .store
            .load_task_run(fixture.taskrun_id)
            .unwrap()
            .current_version,
        new_version
    );
    assert_eq!(
        fixture
            .database
            .store
            .load_conversation(fixture.conversation_id)
            .unwrap()
            .current_version,
        fixture.started.conversation_version
    );
    let taskrun = TaskRun::replay(
        &fixture
            .database
            .store
            .load_task_run(fixture.taskrun_id)
            .unwrap()
            .events,
    )
    .unwrap();
    assert_eq!(taskrun.state(), TaskRunState::Cancelling);
}
use runne_application::{
    commands::{
        CancelTaskRunInput, CommandOutcome, ConversationTextCompletion, FinishConversationTextInput,
    },
    conversation_text_service::{ConversationTextCommandService, ConversationTextService},
    ports::{ConversationRepository, D2ToolLoopCancellationEvidence, EventStore},
};
use runne_domain::task_run::{TaskRun, TaskRunState};
