#[test]
fn canonical_workspace_conversation_reference_is_scoped_to_opaque_workspace_id() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open(&directory.path().join("profile.sqlite3")).expect("open core");
    let workspace_id = CanonicalId::parse("01890e00-0000-7000-8000-000000000002").expect("workspace");

    let reference = core
        .load_or_prepare_workspace_conversation_reference(&workspace_id.to_string())
        .expect("workspace reference");
    assert_eq!(reference.workspace_id(), workspace_id);
    let key = format!("runtime.conversation.workspace.{workspace_id}");
    let stored = core
        .store
        .lock()
        .expect("store")
        .get_setting(&key)
        .expect("read")
        .expect("stored reference");
    assert!(stored.contains(&workspace_id.to_string()));
}

#[test]
fn workspace_subscription_reference_does_not_create_unadmitted_state() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open(&directory.path().join("profile.sqlite3")).expect("open core");

    let error = core
        .load_workspace_conversation_reference("01890e00-0000-7000-8000-000000000002")
        .expect_err("unopened workspace must not create a reference");
    assert_eq!(error.to_string(), "project is unavailable");
}
