fn workspace_files_schema() -> serde_json::Value {
    let path = serde_json::json!({
        "maxLength": runne_api::MAX_WORKSPACE_FILE_PATH_BYTES,
        "minLength": 1,
        "pattern": "^(?!/)(?!.*//)(?!.*(?:^|/)(?:\\.|\\.\\.)(?:/|$))[^\\u0000-\\u001f\\\\]+(?:/[^\\u0000-\\u001f\\\\]+)*$",
        "type": "string",
        "x-gocode-maxUtf8Bytes": runne_api::MAX_WORKSPACE_FILE_PATH_BYTES,
    });
    let entry = || {
        closed_object(
            serde_json::json!({
                "kind": {"enum": ["file", "directory"], "type": "string"},
                "path": path.clone(),
                "sizeBytes": {"minimum": 0, "type": "integer"},
            }),
            &["path", "kind", "sizeBytes"],
        )
    };
    let page = closed_object(
        serde_json::json!({
            "items": {
                "items": {"$ref": "#/$defs/entry"},
                "maxItems": runne_api::MAX_WORKSPACE_FILE_PAGE_SIZE,
                "type": "array",
            },
        }),
        &["items"],
    );
    let content = closed_object(
        serde_json::json!({
            "content": {
                "maxLength": runne_api::MAX_WORKSPACE_FILE_CONTENT_BYTES,
                "type": "string",
                "x-gocode-maxUtf8Bytes": runne_api::MAX_WORKSPACE_FILE_CONTENT_BYTES,
            },
            "path": path,
            "sizeBytes": {"minimum": 0, "type": "integer"},
        }),
        &["path", "content", "sizeBytes"],
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
            "entry": {"$ref": "#/$defs/entry"},
            "page": {"$ref": "#/$defs/page"},
            "content": {"$ref": "#/$defs/content"},
            "error": {"$ref": "#/$defs/error"},
        }),
        &["entry", "page", "content", "error"],
    );
    let object = schema.as_object_mut().expect("closed object");
    object.insert(
        "$defs".to_owned(),
        serde_json::json!({
            "entry": entry(),
            "page": page,
            "content": content,
            "error": error,
        }),
    );
    object.insert(
        "$id".to_owned(),
        serde_json::json!("gocode://schemas/workspace-files-v1"),
    );
    object.insert("$schema".to_owned(), serde_json::json!(DRAFT_2020_12));
    object.insert(
        "title".to_owned(),
        serde_json::json!("Workspace Files V1"),
    );
    schema
}

fn workspace_files_golden() -> serde_json::Value {
    serde_json::json!({
        "content": {
            "content": "fn main() {}\\n",
            "path": "src/main.rs",
            "sizeBytes": 13,
        },
        "entry": {
            "kind": "file",
            "path": "src/main.rs",
            "sizeBytes": 13,
        },
        "page": {"items": []},
    })
}
