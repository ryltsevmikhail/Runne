fn workspace_diffs_openapi(document: &mut serde_json::Value) {
    let schema = "schemas/workspace-diffs-v1.schema.json#/$defs/";
    let path_pattern =
        "^(?!/)(?!.*//)(?!.*(?:^|/)(?:\\.|\\.\\.)(?:/|$))[^\\u0000-\\u001f\\u007f\\\\]+(?:/[^\\u0000-\\u001f\\u007f\\\\]+)*$";
    let id = serde_json::json!({"in": "path", "name": "workspaceId", "required": true, "schema": {"pattern": UUID_V7_PATTERN, "type": "string"}});
    let error = || serde_json::json!({"content": {"application/json": {"schema": {"$ref": format!("{schema}error")}}}, "description": "Canonical error"});
    let paths = document.get_mut("paths").and_then(serde_json::Value::as_object_mut).expect("OpenAPI paths object");
    paths.insert("/v1/workspaces/{workspaceId}/changes".to_owned(), serde_json::json!({
        "get": {
            "parameters": [id.clone(), {"in": "query", "name": "limit", "required": false, "schema": {"default": 50, "maximum": runne_api::MAX_WORKSPACE_CHANGE_PAGE_SIZE, "minimum": 1, "type": "integer"}}],
            "responses": {"200": {"content": {"application/json": {"schema": {"$ref": format!("{schema}page")}}}, "description": "Bounded Workspace changes"}, "400": error(), "401": error(), "404": error(), "503": error()},
            "security": [{"sessionAuth": []}],
        },
    }));
    paths.insert("/v1/workspaces/{workspaceId}/diff".to_owned(), serde_json::json!({
        "get": {
            "parameters": [id, {"in": "query", "name": "path", "required": true, "schema": {"maxLength": runne_api::MAX_WORKSPACE_FILE_PATH_BYTES, "minLength": 1, "pattern": path_pattern, "type": "string", "x-gocode-maxUtf8Bytes": runne_api::MAX_WORKSPACE_FILE_PATH_BYTES}}],
            "responses": {"200": {"content": {"application/json": {"schema": {"$ref": format!("{schema}diff")}}}, "description": "Bounded structured Workspace diff"}, "400": error(), "401": error(), "404": error(), "413": error(), "415": error(), "503": error()},
            "security": [{"sessionAuth": []}],
        },
    }));
}
