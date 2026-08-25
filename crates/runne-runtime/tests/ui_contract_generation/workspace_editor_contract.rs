#[test]
fn workspace_editor_contract_is_closed_and_advertised() {
    let output = tempfile::tempdir().unwrap();
    generate_ui_contract(output.path()).unwrap();
    let schema: Value = serde_json::from_slice(
        &fs::read(
            output
                .path()
                .join("schemas/workspace-editor-v1.schema.json"),
        )
        .unwrap(),
    )
    .unwrap();
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema)
        .expect("editor schema compiles");
    for definition in ["request", "receipt", "error"] {
        assert_eq!(schema["$defs"][definition]["additionalProperties"], false);
    }
    assert_eq!(
        schema["$defs"]["request"]["properties"]["target"]["const"],
        "system_default"
    );

    let openapi: Value = serde_json::from_slice(
        &fs::read(output.path().join("openapi.json")).unwrap(),
    )
    .unwrap();
    let operation = &openapi["paths"]["/v1/workspaces/{workspaceId}/editor"]["post"];
    assert_eq!(operation["requestBody"]["required"], true);
    assert_eq!(
        operation["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        "schemas/workspace-editor-v1.schema.json#/$defs/request"
    );
    assert_eq!(
        operation["responses"]["202"]["content"]["application/json"]["schema"]["$ref"],
        "schemas/workspace-editor-v1.schema.json#/$defs/receipt"
    );
    assert!(RUNTIME_CAPABILITY_CATALOG.contains(&"workspace.editor.open.v1"));
}
