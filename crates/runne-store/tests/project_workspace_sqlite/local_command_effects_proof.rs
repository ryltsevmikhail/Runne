use super::claim::node_registration;
use super::support::*;
use runne_application::commands::{CancelTaskRunInput, CommandOutcome};
use runne_application::conversation_service::ConversationService;
use runne_application::ports::{EventStore, ExecutionNodeId, TaskRunClaimResult};
use runne_domain::id::{ConversationId, WorkspaceId};

#[test]
fn cancelled_local_row_without_terminal_receipt_is_corrupt() {
    let database = Database::new("local-command-effects-missing-terminal-proof");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let conversation_id = ConversationId::from_bytes(command(0x91).into_bytes());
    ConversationService::new(database.store.clone(), database.store.clone(), authority())
        .create_from_application(
            &task_context(0x91, "local-effects-proof-conversation"),
            runne_api::CreateConversationInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                command_id: command(0x91),
                idempotency_key: key("local-effects-proof-conversation"),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
    let local = runne_domain::task_run::TaskRunLocalCommand::new(
        runne_domain::task_run::TaskRunExecutable::workspace_relative("bin/tool".into()).unwrap(),
        ".".into(),
        vec!["tool".into()],
        vec![],
    )
    .unwrap();
    let submitted = database
        .task_runs()
        .submit_task_run(
            &task_context(0x92, "local-effects-proof-submit"),
            runne_application::commands::SubmitTaskRunInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                input: runne_domain::task_run::TaskRunInput::new("description".into())
                    .unwrap()
                    .with_local_command(local)
                    .unwrap(),
            },
        )
        .unwrap();
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = submitted else {
        panic!("TaskRun submission expected")
    };
    let (node_id, node_epoch) = node_registration(&database);
    let claim = database
        .task_runs()
        .claim_task_run(
            &task_context(0x93, "local-effects-proof-claim"),
            runne_application::service::ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: ExecutionNodeId(node_id.clone()),
                node_epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 30_000,
            },
            &database.store,
        )
        .unwrap();
    let TaskRunClaimResult::Committed(claim) = claim else {
        panic!("fresh local claim expected")
    };
    database
        .task_runs()
        .cancel_task_run(
            &task_context(0x94, "local-effects-proof-cancel"),
            CancelTaskRunInput {
                taskrun_id,
                expected_version: 4,
            },
        )
        .unwrap();
    let before = database.store.load_task_run(taskrun_id).unwrap();
    assert_eq!(before.current_version, 5);

    let connection = database.connection();
    connection
        .execute_batch(
            "DROP TRIGGER taskrun_local_command_identity_immutable;
             DROP TRIGGER taskrun_local_command_state_transition;",
        )
        .unwrap();
    let node = *uuid::Uuid::parse_str(&node_id).unwrap().as_bytes();
    connection
        .execute(
            "UPDATE taskrun_local_command_attempts
             SET attempt_id=?1,node_id=?2,node_epoch=?3,fence=?4,
                 managed_area_identity=?5,state='cancelled'
             WHERE taskrun_id=?6",
            rusqlite::params![
                claim.attempt_id.as_bytes(),
                node,
                node_epoch as i64,
                claim.fence.0 as i64,
                [0x71u8; 100].as_slice(),
                taskrun_id.as_bytes(),
            ],
        )
        .unwrap();

    let result = database.store.load_task_run_effects(taskrun_id);
    assert!(matches!(
        result,
        Err(runne_application::ports::EventStoreError::CorruptData)
    ));
    assert_eq!(
        database
            .store
            .load_task_run(taskrun_id)
            .unwrap()
            .current_version,
        before.current_version,
        "the rejected projection preserves the exact cancelling stream"
    );
}
