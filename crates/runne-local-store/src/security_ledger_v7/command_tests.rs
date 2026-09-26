use super::NormalizedMutationCommand;
use crate::BoundedCanonicalId;

#[test]
fn text_only_command_has_a_distinct_durable_tag_and_round_trips() {
    let conversation_id =
        BoundedCanonicalId::parse(b"018f2e3a-7000-7000-8000-000000000903").unwrap();
    let workspace_id = BoundedCanonicalId::parse(b"018f2e3a-7000-7000-8000-000000000902").unwrap();
    let workspace = NormalizedMutationCommand::CreateConversation {
        conversation_id: conversation_id.clone(),
        workspace_id: workspace_id.clone(),
    };
    let text_only = NormalizedMutationCommand::CreateTextOnlyConversation {
        conversation_id,
        workspace_id,
    };

    let workspace_bytes = workspace.encode().unwrap();
    let text_only_bytes = text_only.encode().unwrap();
    assert_eq!(workspace_bytes[1], 7);
    assert_eq!(text_only_bytes[1], 14);
    assert_ne!(workspace_bytes, text_only_bytes);
    assert_eq!(
        NormalizedMutationCommand::decode(&workspace_bytes).unwrap(),
        workspace
    );
    assert_eq!(
        NormalizedMutationCommand::decode(&text_only_bytes).unwrap(),
        text_only
    );
}
