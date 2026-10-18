use super::*;

#[test]
fn compiled_route_rejects_legacy_approval_binding() {
    let database = Database::new("compiled-route-rejects-legacy-binding");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let conversation_id = ConversationId::from_bytes(command(0xb1).into_bytes());
    ConversationService::new(database.store.clone(), database.store.clone(), authority())
        .create_from_application(
            &task_context(0xb1, "compiled-route-conversation"),
            runne_api::CreateConversationInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                command_id: command(0xb1),
                idempotency_key: key("compiled-route-conversation"),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
    let local = TaskRunLocalCommand::new(
        TaskRunExecutable::workspace_relative("bin/tool".into()).unwrap(),
        ".".into(),
        vec!["tool".into()],
        vec![],
    )
    .unwrap();
    let outcome = database
        .task_runs()
        .submit_task_run(
            &task_context(0xb2, "compiled-route-submit"),
            runne_application::commands::SubmitTaskRunInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                input: TaskRunInput::new("description".into())
                    .unwrap()
                    .with_local_command(local.clone())
                    .unwrap(),
            },
        )
        .unwrap();
    let runne_application::commands::CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome
    else {
        panic!("submitted local TaskRun")
    };
    let binding = LocalCommandApprovalBinding {
        command_digest: local.intent_digest(),
        executable_digest: [0x31; 32],
        workspace_version: 1,
        admitted_root_version: 1,
        admitted_root_identity: [0x32; 32],
        trust_epoch: 1,
        trust_revision: 1,
        source_policy_version: 2,
        command_policy_version: 1,
        approval_id: *ApprovalId::from_bytes(command(0xb3).into_bytes()).as_bytes(),
    };
    assert!(
        database
            .store
            .bind_local_command_approval(
                taskrun_id,
                binding,
                LocalCommandAttemptState::ApprovalPending,
            )
            .is_err()
    );
    let route: (i64, i64, i64) = database
        .connection()
        .query_row(
            "SELECT route,provenance,cutover_version FROM taskrun_local_permission_routes WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(route, (2, 3, 68));
}
