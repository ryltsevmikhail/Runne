use runne_provider::{ProviderToolDeclarationV1, ProviderToolNameV1};

#[test]
fn coding_tools_have_closed_names_and_bounded_schemas() {
    for name in [
        "workspace_files_list",
        "workspace_files_search",
        "workspace_file_replace",
        "workspace_command_run",
    ] {
        let tool = ProviderToolNameV1::from_wire_name(name).expect("coding tool is declared");
        assert_eq!(tool.wire_name(), name);
        let declaration = ProviderToolDeclarationV1::for_name(tool);
        assert_eq!(declaration.parameters()["additionalProperties"], false);
        assert!(
            !declaration.parameters()["required"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    assert!(ProviderToolNameV1::from_wire_name("shell").is_none());
}

#[test]
fn legacy_file_schemas_remain_unchanged() {
    let read = ProviderToolDeclarationV1::for_name(ProviderToolNameV1::WorkspaceFileRead);
    assert_eq!(
        read.parameters(),
        &serde_json::json!({"type":"object", "properties":{"path":{"type":"string","maxLength":255}},"required":["path"],"additionalProperties":false})
    );
}
