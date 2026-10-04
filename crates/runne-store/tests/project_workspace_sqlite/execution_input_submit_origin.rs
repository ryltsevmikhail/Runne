use super::execution_input::claim;
use super::submit_fence::submit_task_run;
use super::support::*;
use runne_application::commands::CommandOutcome;
use runne_application::conversation_service::ConversationService;
use runne_application::ports::TaskRunExecutionInputPort;
use runne_domain::id::{ConversationId, WorkspaceId};

#[test]
fn local_command_submit_atomically_persists_writer_occupation_intent() {
    let database = Database::new("local-command-submit-intent");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let conversation_id = ConversationId::from_bytes(command(0x38).into_bytes());
    ConversationService::new(database.store.clone(), database.store.clone(), authority())
        .create_from_application(
            &task_context(0x39, "local-command-conversation"),
            runne_api::CreateConversationInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                command_id: command(0x39),
                idempotency_key: key("local-command-conversation"),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
    let command = runne_domain::task_run::TaskRunLocalCommand::new(
        runne_domain::task_run::TaskRunExecutable::workspace_relative("bin/tool".into()).unwrap(),
        ".".into(),
        vec!["tool".into(), "--safe".into()],
        vec![],
    )
    .unwrap();
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = database
        .task_runs()
        .submit_task_run(
            &task_context(0x3a, "local-command-submit"),
            runne_application::commands::SubmitTaskRunInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                input: runne_domain::task_run::TaskRunInput::new("description".into())
                    .unwrap()
                    .with_local_command(command.clone())
                    .unwrap(),
            },
        )
        .unwrap()
    else {
        panic!("submitted")
    };
    let row: (Vec<u8>, String) = database
        .connection()
        .query_row(
            "SELECT command_digest,state FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(row.0, command.intent_digest());
    assert_eq!(row.1, "preflight");
}

#[test]
fn preserves_optional_model_from_the_exact_submitted_receipt() {
    let database = Database::new("execution-input-model-v2");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let tail = 0x2a;
    let conversation_id = ConversationId::from_bytes(command(tail + 0x10).into_bytes());
    ConversationService::new(database.store.clone(), database.store.clone(), authority())
        .create_from_application(
            &task_context(tail + 0x20, "model-input-conversation"),
            runne_api::CreateConversationInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                command_id: command(tail + 0x20),
                idempotency_key: key("model-input-conversation"),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
    let outcome = database
        .task_runs()
        .submit_task_run(
            &task_context(tail, "model-input-submit"),
            runne_application::commands::SubmitTaskRunInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                input: runne_domain::task_run::TaskRunInput::new("model prompt".to_owned())
                    .unwrap()
                    .with_requested_model("provider/model-v2".to_owned())
                    .unwrap(),
            },
        )
        .unwrap();
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome else {
        panic!("submitted")
    };
    let execution = database
        .store
        .read_taskrun_execution_input(claim(&database, taskrun_id, tail + 1), 4)
        .unwrap();
    assert_eq!(execution.input.prompt(), "model prompt");
    assert_eq!(
        execution.requested_model.as_deref(),
        Some("provider/model-v2")
    );
}

#[test]
fn rejects_execution_when_submit_receipt_authority_witness_is_tampered() {
    for (index, field) in [
        "idempotency_key",
        "fingerprint",
        "command_outcome",
        "lineage",
    ]
    .into_iter()
    .enumerate()
    {
        let tail = 0x80 + index as u8 * 4;
        let database = Database::new(&format!("execution-input-submit-{field}"));
        let repository = database.repository();
        create_project(&repository);
        create_workspace(&repository);
        let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } =
            submit_task_run(&database, tail, "input-submit-witness")
        else {
            panic!("submitted")
        };
        let identity = claim(&database, taskrun_id, tail + 1);
        if field == "lineage" {
            database
                .connection()
                .execute(
                    "DELETE FROM task_run_workspace_lineage WHERE taskrun_id=?1",
                    [taskrun_id.as_bytes()],
                )
                .unwrap();
        } else {
            let sql = format!(
                "UPDATE command_receipts SET {field}=?1 WHERE command_id=(
                    SELECT command_id FROM events WHERE aggregate_type=1 AND aggregate_id=?2 AND sequence=1
                )"
            );
            let replacement: Vec<u8> = if field == "idempotency_key" {
                b"different-submit-key".to_vec()
            } else if field == "fingerprint" {
                vec![0; 32]
            } else {
                vec![0]
            };
            database
                .connection()
                .execute(&sql, rusqlite::params![replacement, taskrun_id.as_bytes()])
                .unwrap();
        }
        assert_eq!(
            database.store.read_taskrun_execution_input(identity, 4),
            Err(runne_application::ports::TaskRunExecutionInputError::CorruptData),
            "tampered {field} must never reach provider execution"
        );
    }
}
