fn workspace_diffs_schema() -> serde_json::Value {
    let path = serde_json::json!({
        "maxLength": runne_api::MAX_WORKSPACE_FILE_PATH_BYTES,
        "minLength": 1,
        "pattern": "^(?!/)(?!.*//)(?!.*(?:^|/)(?:\\.|\\.\\.)(?:/|$))[^\\u0000-\\u001f\\u007f\\\\]+(?:/[^\\u0000-\\u001f\\u007f\\\\]+)*$",
        "type": "string",
        "x-gocode-maxUtf8Bytes": runne_api::MAX_WORKSPACE_FILE_PATH_BYTES,
    });
    let change_kind = serde_json::json!({"enum": ["added", "modified", "deleted"], "type": "string"});
    let entry = closed_object(
        serde_json::json!({
            "additions": {"minimum": 0, "type": "integer"},
            "deletions": {"minimum": 0, "type": "integer"},
            "kind": change_kind.clone(),
            "path": path.clone(),
        }),
        &["path", "kind", "additions", "deletions"],
    );
    let line = closed_object(
        serde_json::json!({
            "kind": {"enum": ["context", "added", "removed"], "type": "string"},
            "text": {"maxLength": runne_api::MAX_WORKSPACE_DIFF_LINE_BYTES, "type": "string", "x-gocode-maxUtf8Bytes": runne_api::MAX_WORKSPACE_DIFF_LINE_BYTES},
        }),
        &["kind", "text"],
    );
    let hunk = closed_object(
        serde_json::json!({
            "oldLines": {"minimum": 0, "type": "integer"},
            "oldStart": {"minimum": 1, "type": "integer"},
            "newLines": {"minimum": 0, "type": "integer"},
            "newStart": {"minimum": 1, "type": "integer"},
            "lines": {"items": {"$ref": "#/$defs/line"}, "maxItems": runne_api::MAX_WORKSPACE_DIFF_LINES_PER_HUNK, "type": "array"},
        }),
        &["oldStart", "oldLines", "newStart", "newLines", "lines"],
    );
    let page = closed_object(
        serde_json::json!({"items": {"items": {"$ref": "#/$defs/entry"}, "maxItems": runne_api::MAX_WORKSPACE_CHANGE_PAGE_SIZE, "type": "array"}}),
        &["items"],
    );
    let mut diff = closed_object(
        serde_json::json!({
            "hunks": {"items": {"$ref": "#/$defs/hunk"}, "maxItems": runne_api::MAX_WORKSPACE_DIFF_HUNKS, "type": "array"},
            "kind": change_kind,
            "path": path,
            "truncated": {"type": "boolean"},
        }),
        &["path", "kind", "hunks", "truncated"],
    );
    diff.as_object_mut().expect("closed object").insert(
        "x-gocode-maxTotalLines".to_owned(),
        serde_json::json!(runne_api::MAX_WORKSPACE_DIFF_LINES),
    );
    let error = closed_object(
        serde_json::json!({"code": {"maxLength": 128, "type": "string"}, "requestId": {"pattern": UUID_V7_PATTERN, "type": "string"}}),
        &["code", "requestId"],
    );
    let mut schema = closed_object(
        serde_json::json!({
            "entry": {"$ref": "#/$defs/entry"},
            "page": {"$ref": "#/$defs/page"},
            "line": {"$ref": "#/$defs/line"},
            "hunk": {"$ref": "#/$defs/hunk"},
            "diff": {"$ref": "#/$defs/diff"},
            "error": {"$ref": "#/$defs/error"},
        }),
        &["entry", "page", "line", "hunk", "diff", "error"],
    );
    let object = schema.as_object_mut().expect("closed object");
    object.insert("$defs".to_owned(), serde_json::json!({"entry": entry, "page": page, "line": line, "hunk": hunk, "diff": diff, "error": error}));
    object.insert("$id".to_owned(), serde_json::json!("gocode://schemas/workspace-diffs-v1"));
    object.insert("$schema".to_owned(), serde_json::json!(DRAFT_2020_12));
    object.insert("title".to_owned(), serde_json::json!("Workspace Diffs V1"));
    schema
}

fn workspace_diffs_golden() -> serde_json::Value {
    serde_json::json!({
        "diff": {"hunks": [], "kind": "modified", "path": "src/main.rs", "truncated": false},
        "entry": {"additions": 1, "deletions": 1, "kind": "modified", "path": "src/main.rs"},
        "line": {"kind": "context", "text": "same"},
        "page": {"items": []},
    })
}
