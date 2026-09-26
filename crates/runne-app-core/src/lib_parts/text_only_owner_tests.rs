#[test]
fn text_only_reference_is_durable_and_distinct_from_workspace_owner() {
    use super::{AppCore, CanonicalId, ConversationReferenceOwner, LocalStore};

    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("profile.sqlite3");
    let workspace_id = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000902").unwrap();
    let (text_conversation, text_workspace, workspace_conversation) = {
        let mut store = LocalStore::open(&path).expect("open store");
        let text = AppCore::load_or_prepare_conversation_reference_in_store(
            &mut store,
            ConversationReferenceOwner::TextOnly,
        )
        .expect("text-only reference");
        let workspace = AppCore::load_or_prepare_conversation_reference_in_store(
            &mut store,
            ConversationReferenceOwner::Workspace(workspace_id),
        )
        .expect("workspace reference");
        assert!(text.text_only());
        assert!(!workspace.text_only());
        assert_ne!(text.conversation_id(), workspace.conversation_id());
        (
            text.conversation_id(),
            text.workspace_id(),
            workspace.conversation_id(),
        )
    };

    let mut reopened = LocalStore::open(&path).expect("reopen store");
    let text = AppCore::load_or_prepare_conversation_reference_in_store(
        &mut reopened,
        ConversationReferenceOwner::TextOnly,
    )
    .expect("restored text-only reference");
    assert!(text.text_only());
    assert_eq!(text.conversation_id(), text_conversation);
    assert_eq!(text.workspace_id(), text_workspace);
    assert_eq!(
        AppCore::load_or_prepare_conversation_reference_in_store(
            &mut reopened,
            ConversationReferenceOwner::Workspace(workspace_id),
        )
        .expect("restored workspace reference")
        .conversation_id(),
        workspace_conversation
    );
}
