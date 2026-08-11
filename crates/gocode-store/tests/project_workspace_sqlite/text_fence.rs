use gocode_api::CreateConversationInput;
use gocode_application::commands::BeginConversationTextInput;
use gocode_application::conversation_service::ConversationService;
use gocode_application::conversation_text_service::ConversationTextService;
use gocode_application::ports::ProjectWorkspaceRepository;
use gocode_domain::id::{ConversationId, ProjectId};
use gocode_domain::message::MessageText;

use super::support::*;

#[test]
fn project_delete_committed_first_blocks_a_text_taskrun_origin() {
    let database = Database::new("pw-delete-before-text-origin");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let conversation_id = ConversationId::from_bytes(command(0x75).into_bytes());
    let context = task_context(50, "create-conversation-before-delete");
    ConversationService::new(database.store.clone(), database.store.clone(), authority())
        .create_from_application(
            &context,
            CreateConversationInput {
                conversation_id,
                workspace_id: gocode_domain::id::WorkspaceId::from_bytes(WORKSPACE),
                command_id: context.command_id,
                idempotency_key: context.idempotency_key.clone(),
            },
        )
        .unwrap();
    database
        .connection()
        .execute(
            "UPDATE workspaces SET live = 0 WHERE workspace_id = ?1",
            [WORKSPACE],
        )
        .unwrap();
    repository
        .delete_project(
            "owner",
            command(51),
            &key("delete-before-text"),
            ProjectId::from_bytes(PROJECT),
            1,
        )
        .unwrap();

    let service = ConversationTextService::new(
        database.store.clone(),
        database.store.clone(),
        authority(),
        guard(),
    );
    assert!(
        service
            .begin(
                &task_context(52, "text-after-delete"),
                BeginConversationTextInput {
                    conversation_id,
                    expected_version: 1,
                    text: MessageText::new("blocked").unwrap(),
                },
            )
            .is_err()
    );
}
