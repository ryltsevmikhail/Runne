#[test]
fn reconciliation_witness_is_constructed_from_every_anchored_command() {
    use runne_local_store::NormalizedMutationCommand as Command;
    let project = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000901").unwrap();
    let workspace = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000902").unwrap();
    let conversation = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000903").unwrap();
    let id = |value: CanonicalId| {
        runne_local_store::BoundedCanonicalId::parse(value.to_string().as_bytes()).unwrap()
    };
    let commands = [
        Command::create_project(id(project), "Project".into()).unwrap(),
        Command::ArchiveProject { project_id: id(project), expected_version: 1 },
        Command::DeleteProject { project_id: id(project), expected_version: 1 },
        Command::CreateWorkspace { workspace_id: id(workspace), project_id: id(project), display_name: "Workspace".into() },
        Command::bind_workspace_root(id(workspace), 1, [9; 32]).unwrap(),
        Command::OpenWorkspace { workspace_id: id(workspace), expected_version: 1 },
        Command::CreateConversation { conversation_id: id(conversation), workspace_id: id(workspace) },
        Command::GenerateText { conversation_id: id(conversation), expected_version: 1, text: "text".into() },
    ];
    for command in commands {
        assert!(reconciliation_request_from_anchored(
            &CommandIdentity::new(CanonicalId::now_v7(), CanonicalId::now_v7().to_string()).unwrap(),
            &command,
        )
        .is_ok());
    }
}

#[test]
fn stored_command_must_exactly_match_the_caller_request() {
    let request = MutationRequest::create_project(CanonicalId::now_v7(), "Project".into()).unwrap();
    let mismatch = runne_local_store::NormalizedMutationCommand::create_project(
        runne_local_store::BoundedCanonicalId::parse(CanonicalId::now_v7().to_string().as_bytes()).unwrap(),
        "Changed".into(),
    )
    .unwrap();
    assert!(request_matches_anchored_command(&request, &mismatch).is_err());
}
