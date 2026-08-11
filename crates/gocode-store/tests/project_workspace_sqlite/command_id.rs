use gocode_api::CreateConversationInput;
use gocode_application::commands::{BeginConversationTextInput, CreateTaskRunInput};
use gocode_application::conversation_service::ConversationService;
use gocode_application::conversation_text_service::ConversationTextService;
use gocode_application::ports::ProjectWorkspaceRepository;
use gocode_domain::id::{ConversationId, WorkspaceId};
use gocode_domain::message::MessageText;

use super::support::*;

#[test]
fn command_id_is_unique_between_project_and_direct_taskrun_in_both_orders() {
    let database = Database::new("pw-command-direct");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    database
        .task_runs()
        .create_task_run(
            &task_context(38, "task-first"),
            CreateTaskRunInput {
                conversation_id: ConversationId::from_bytes(command(0x40).into_bytes()),
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
            },
        )
        .unwrap();
    assert!(
        repository
            .create_project(
                "owner",
                command(38),
                &key("project-after-task"),
                project(PROJECT_2, "Two"),
            )
            .is_err()
    );

    repository
        .create_project(
            "owner",
            command(39),
            &key("project-first"),
            project(PROJECT_2, "Two"),
        )
        .unwrap();
    assert!(
        database
            .task_runs()
            .create_task_run(
                &task_context(39, "task-after-project"),
                CreateTaskRunInput {
                    conversation_id: ConversationId::from_bytes(command(0x41).into_bytes()),
                    workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                },
            )
            .is_err()
    );
}

#[test]
fn project_command_id_blocks_conversation_and_text_receipt_writers() {
    let database = Database::new("pw-command-conversation-text");
    let repository = database.repository();
    create_project(&repository);
    let conversation_id = ConversationId::from_bytes(command(0x42).into_bytes());
    let conversation_service =
        ConversationService::new(database.store.clone(), database.store.clone(), authority());

    repository
        .create_project(
            "owner",
            command(40),
            &key("reserve-conversation-command"),
            project(PROJECT_2, "Two"),
        )
        .unwrap();
    assert!(
        conversation_service
            .create_from_application(
                &task_context(40, "conversation-collision"),
                CreateConversationInput {
                    conversation_id,
                    workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                    command_id: command(40),
                    idempotency_key: key("conversation-collision"),
                },
            )
            .is_err()
    );
    conversation_service
        .create_from_application(
            &task_context(41, "conversation-create"),
            CreateConversationInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                command_id: command(41),
                idempotency_key: key("conversation-create"),
            },
        )
        .unwrap();
    repository
        .archive_project(
            "owner",
            command(42),
            &key("reserve-text-command"),
            gocode_domain::id::ProjectId::from_bytes(PROJECT),
            1,
        )
        .unwrap();
    let text = ConversationTextService::new(
        database.store.clone(),
        database.store.clone(),
        authority(),
        guard(),
    );
    assert!(
        text.begin(
            &task_context(42, "text-collision"),
            BeginConversationTextInput {
                conversation_id,
                expected_version: 1,
                text: MessageText::new("hello").unwrap(),
            },
        )
        .is_err()
    );
    text.begin(
        &task_context(43, "text-first"),
        BeginConversationTextInput {
            conversation_id,
            expected_version: 1,
            text: MessageText::new("hello").unwrap(),
        },
    )
    .unwrap();
    assert!(
        repository
            .restore_project(
                "owner",
                command(43),
                &key("project-after-text"),
                gocode_domain::id::ProjectId::from_bytes(PROJECT),
                2,
            )
            .is_err()
    );
}
