fn workspace_files_openapi(document: &mut serde_json::Value) {
    let schema = "schemas/workspace-files-v1.schema.json#/$defs/";
    let id = serde_json::json!({
        "in": "path",
        "name": "workspaceId",
        "required": true,
        "schema": {"pattern": UUID_V7_PATTERN, "type": "string"},
    });
    let path = serde_json::json!({
        "in": "query",
        "name": "path",
        "required": false,
        "schema": {"maxLength": runne_api::MAX_WORKSPACE_FILE_PATH_BYTES, "type": "string"},
    });
    let limit = serde_json::json!({
        "in": "query",
        "name": "limit",
        "required": false,
        "schema": {
            "default": 50,
            "maximum": runne_api::MAX_WORKSPACE_FILE_PAGE_SIZE,
            "minimum": 1,
            "type": "integer",
        },
    });
    let error = || {
        serde_json::json!({
            "content": {"application/json": {"schema": {"$ref": format!("{schema}error")}}},
            "description": "Canonical error",
        })
    };
    let paths = document
        .get_mut("paths")
        .and_then(serde_json::Value::as_object_mut)
        .expect("OpenAPI paths object");
    paths.insert(
        "/v1/workspaces/{workspaceId}/files".to_owned(),
        serde_json::json!({
            "get": {
                "parameters": [id.clone(), path, limit],
                "responses": {
                    "200": {
                        "content": {"application/json": {"schema": {"$ref": format!("{schema}page")}}},
                        "description": "Bounded Workspace file page",
                    },
                    "400": error(),
                    "401": error(),
                    "404": error(),
                    "413": error(),
                    "503": error(),
                },
                "security": [{"sessionAuth": []}],
            },
        }),
    );
    paths.insert(
        "/v1/workspaces/{workspaceId}/files/content".to_owned(),
        serde_json::json!({
            "get": {
                "parameters": [
                    id,
                    {
                        "in": "query",
                        "name": "path",
                        "required": true,
                        "schema": {"maxLength": runne_api::MAX_WORKSPACE_FILE_PATH_BYTES, "minLength": 1, "type": "string"},
                    },
                ],
                "responses": {
                    "200": {
                        "content": {"application/json": {"schema": {"$ref": format!("{schema}content")}}},
                        "description": "Bounded UTF-8 Workspace file",
                    },
                    "400": error(),
                    "401": error(),
                    "404": error(),
                    "413": error(),
                    "415": error(),
                    "503": error(),
                },
                "security": [{"sessionAuth": []}],
            },
        }),
    );
}
