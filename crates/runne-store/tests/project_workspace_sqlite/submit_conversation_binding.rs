use runne_application::commands::{LegacySubmitTaskRunInput, SubmitTaskRunInput};
use runne_application::conversation_service::ConversationService;
use runne_application::ports::ProjectWorkspaceRepository;
use runne_domain::id::{ConversationId, WorkspaceId};

use super::support::*;

fn create_conversation(database: &Database, id: u8, workspace: [u8; 16], text_only: bool) {
    ConversationService::new(database.store.clone(), database.store.clone(), authority())
        .create_from_application(
            &task_context(id + 0x20, &format!("binding-conversation-{id}")),
            runne_api::CreateConversationInput {
                conversation_id: ConversationId::from_bytes(command(id).into_bytes()),
                workspace_id: WorkspaceId::from_bytes(workspace),
                command_id: command(id + 0x20),
                idempotency_key: key(&format!("binding-conversation-{id}")),
                scope: if text_only {
                    runne_api::ConversationContextScope::TextOnly
                } else {
                    runne_api::ConversationContextScope::Workspace
                },
            },
        )
        .unwrap();
}

fn submit(
    database: &Database,
    id: u8,
    conversation: u8,
) -> Result<runne_application::commands::CommandOutcome, runne_application::errors::ApplicationError>
{
    database.task_runs().submit_task_run(
        &task_context(id, &format!("binding-submit-{id}")),
        SubmitTaskRunInput {
            conversation_id: ConversationId::from_bytes(command(conversation).into_bytes()),
            workspace_id: WorkspaceId::from_bytes(WORKSPACE),
            input: runne_domain::task_run::TaskRunInput::new("prompt".into()).unwrap(),
        },
    )
}

fn assert_no_submit_write(database: &Database, command_id: u8) {
    let connection = database.connection();
    for (sql, expected) in [
        ("SELECT COUNT(*) FROM events WHERE aggregate_type = 1", 0),
        (
            "SELECT COUNT(*) FROM aggregate_streams WHERE aggregate_type = 1",
            0,
        ),
        ("SELECT COUNT(*) FROM task_run_workspace_lineage", 0),
    ] {
        let count: i64 = connection.query_row(sql, [], |row| row.get(0)).unwrap();
        assert_eq!(count, expected, "unexpected submit state in `{sql}`");
    }
    let receipt: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM command_receipts WHERE command_id = ?1",
            [command(command_id).as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(receipt, 0, "rejected submit must not record a receipt");
}

#[test]
fn submit_requires_canonical_conversation_in_requested_workspace() {
    let database = Database::new("pw-submit-binding-missing");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    assert!(submit(&database, 0xb1, 0xb2).is_err());
    assert_no_submit_write(&database, 0xb1);
}

#[test]
fn submit_rejects_conversation_bound_to_another_workspace_atomically() {
    let database = Database::new("pw-submit-binding-mismatch");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    repository
        .create_workspace(
            "owner",
            command(0xb3),
            &key("binding-other-workspace"),
            workspace(
                [
                    0x01, 0x8f, 0x47, 0xa2, 0x4f, 0x8c, 0x7b, 0x52, 0x8c, 0x35, 0x7a, 0x3a, 0x14,
                    0xc2, 0xd9, 0x22,
                ],
                PROJECT,
                "Other",
            ),
        )
        .unwrap();
    let other = [
        0x01, 0x8f, 0x47, 0xa2, 0x4f, 0x8c, 0x7b, 0x52, 0x8c, 0x35, 0x7a, 0x3a, 0x14, 0xc2, 0xd9,
        0x22,
    ];
    create_conversation(&database, 0xb4, other, false);
    assert!(submit(&database, 0xb5, 0xb4).is_err());
    assert_no_submit_write(&database, 0xb5);
}

#[test]
fn submit_rejects_text_only_conversation_atomically() {
    let database = Database::new("pw-submit-binding-text-only");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    create_conversation(&database, 0xb6, WORKSPACE, true);
    assert!(submit(&database, 0xb7, 0xb6).is_err());
    assert_no_submit_write(&database, 0xb7);
}

#[test]
fn submit_rejects_unclassified_conversation_atomically() {
    let database = Database::new("pw-submit-binding-unclassified");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    create_conversation(&database, 0xb8, WORKSPACE, false);
    database
        .connection()
        .execute(
            "DELETE FROM conversation_context_scope WHERE conversation_id = ?1",
            [command(0xb8).as_bytes()],
        )
        .unwrap();
    assert!(submit(&database, 0xb9, 0xb8).is_err());
    assert_no_submit_write(&database, 0xb9);
}

#[test]
fn legacy_submit_keeps_promptless_lineage_semantics() {
    let database = Database::new("pw-submit-binding-legacy");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    create_conversation(&database, 0xc2, WORKSPACE, false);
    let outcome = database
        .task_runs()
        .submit_task_run_legacy(
            &task_context(0xc1, "binding-submit-legacy"),
            LegacySubmitTaskRunInput {
                conversation_id: ConversationId::from_bytes(command(0xc2).into_bytes()),
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
            },
        )
        .expect("v1 submit retains its historical conversation lineage behavior");
    assert!(matches!(
        outcome,
        runne_application::commands::CommandOutcome::TaskRunSubmitted { new_version: 2, .. }
    ));
    let lineage: (i64, i64) = database
        .connection()
        .query_row(
            "SELECT COUNT(*), MIN(origin_operation) FROM task_run_workspace_lineage",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(lineage, (1, 20));
}
