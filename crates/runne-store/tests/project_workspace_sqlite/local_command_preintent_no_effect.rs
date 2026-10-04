#![cfg(target_os = "linux")]

use super::claim::node_registration;
use super::support::*;
use runne_application::commands::CommandOutcome;
use runne_application::conversation_service::ConversationService;
use runne_application::ports::{
    EventStore, ExecutionNodeId, TaskRunClaimResult, TaskRunNoEffectScanRequest,
    TaskRunNoEffectScanner,
};
use runne_domain::id::{ConversationId, WorkspaceId};

#[path = "local_command_preintent_no_effect/approval_cases.rs"]
mod approval_cases;

#[test]
fn restart_releases_only_unbound_local_preintent_as_no_effect() {
    let database = Database::new("local-command-preintent-no-effect");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let conversation_id = ConversationId::from_bytes(command(0x64).into_bytes());
    ConversationService::new(database.store.clone(), database.store.clone(), authority())
        .create_from_application(
            &task_context(0x64, "local-command-preintent-conversation"),
            runne_api::CreateConversationInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                command_id: command(0x64),
                idempotency_key: key("local-command-preintent-conversation"),
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
    let outcome = database
        .task_runs()
        .submit_task_run(
            &task_context(0x65, "local-command-preintent-submit"),
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
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome else {
        panic!("submitted local TaskRun")
    };
    let (node_id, epoch) = node_registration(&database);
    let claim = database
        .task_runs()
        .claim_task_run(
            &task_context(0x66, "local-command-preintent-claim"),
            runne_application::service::ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: ExecutionNodeId(node_id.clone()),
                node_epoch: epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 30_000,
            },
            &database.store,
        )
        .unwrap();
    let TaskRunClaimResult::Committed(claim) = claim else {
        panic!("fresh claim")
    };
    let (current_node, current_epoch) = node_registration(&database);
    assert_eq!(current_node, node_id);
    let reopened = crate::validated_reopen::reopen_store(
        database.file.path(),
        database.identity,
        authority(),
        guard(),
    )
    .unwrap();
    let page = reopened
        .scan_no_effect_assignments(
            TaskRunNoEffectScanRequest::new(None, 8, ExecutionNodeId(current_node), current_epoch)
                .unwrap(),
        )
        .unwrap();
    assert_eq!(page.candidates.len(), 1);
    assert_eq!(page.candidates[0].identity.taskrun_id, taskrun_id);
    let settled = database
        .task_runs()
        .settle_taskrun_no_effect(
            &task_context(0x67, "local-command-preintent-release"),
            page.candidates[0].clone(),
            &reopened,
        )
        .unwrap();
    assert!(matches!(
        settled,
        runne_application::ports::TaskRunNoEffectReleaseResult::Released(_)
    ));
    let state: String = database
        .connection()
        .query_row(
            "SELECT state FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "no_effect_terminal");
    let occupation: String = database
        .connection()
        .query_row(
            "SELECT state FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2",
            rusqlite::params![taskrun_id.as_bytes(), claim.fence.0 as i64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(occupation, "released");
    let reopened = crate::validated_reopen::reopen_store(
        database.file.path(),
        database.identity,
        authority(),
        guard(),
    )
    .unwrap();
    let stream = reopened.load_task_run(taskrun_id).unwrap();
    assert_eq!(
        runne_domain::task_run::TaskRun::replay(&stream.events)
            .unwrap()
            .state(),
        runne_domain::task_run::TaskRunState::Failed
    );
}
