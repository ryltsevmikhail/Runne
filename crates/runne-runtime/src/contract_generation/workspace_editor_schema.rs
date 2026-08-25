fn workspace_editor_schema() -> serde_json::Value {
    let path = serde_json::json!({
        "maxLength": runne_api::MAX_WORKSPACE_FILE_PATH_BYTES,
        "minLength": 1,
        "pattern": "^(?!/)(?!.*//)(?!.*(?:^|/)(?:\\.|\\.\\.)(?:/|$))[^\\u0000-\\u001f\\\\]+(?:/[^\\u0000-\\u001f\\\\]+)*$",
        "type": "string",
        "x-gocode-maxUtf8Bytes": runne_api::MAX_WORKSPACE_FILE_PATH_BYTES,
    });
    let request = closed_object(
        serde_json::json!({
            "relativePath": path,
            "target": {"const": "system_default", "type": "string"},
        }),
        &["relativePath", "target"],
    );
    let receipt = closed_object(
        serde_json::json!({
            "target": {"const": "system_default", "type": "string"},
            "workspaceId": {"pattern": UUID_V7_PATTERN, "type": "string"},
        }),
        &["workspaceId", "target"],
    );
    let error = closed_object(
        serde_json::json!({
            "code": {"maxLength": 128, "type": "string"},
            "requestId": {"pattern": UUID_V7_PATTERN, "type": "string"},
        }),
        &["code", "requestId"],
    );
    let mut schema = closed_object(
        serde_json::json!({
            "error": {"$ref": "#/$defs/error"},
            "receipt": {"$ref": "#/$defs/receipt"},
            "request": {"$ref": "#/$defs/request"},
        }),
        &["request", "receipt", "error"],
    );
    let object = schema.as_object_mut().expect("closed object");
    object.insert(
        "$defs".to_owned(),
        serde_json::json!({"error": error, "receipt": receipt, "request": request}),
    );
    object.insert(
        "$id".to_owned(),
        serde_json::json!("gocode://schemas/workspace-editor-v1"),
    );
    object.insert("$schema".to_owned(), serde_json::json!(DRAFT_2020_12));
    object.insert("title".to_owned(), serde_json::json!("Workspace Editor V1"));
    schema
}
