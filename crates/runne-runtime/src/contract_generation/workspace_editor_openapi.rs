fn workspace_editor_openapi(document: &mut serde_json::Value) {
    let schema = "schemas/workspace-editor-v1.schema.json#/$defs/";
    let error = || serde_json::json!({
        "content": {"application/json": {"schema": {"$ref": format!("{schema}error")}}},
        "description": "Canonical error",
    });
    let paths = document
        .get_mut("paths")
        .and_then(serde_json::Value::as_object_mut)
        .expect("OpenAPI paths object");
    paths.insert(
        "/v1/workspaces/{workspaceId}/editor".to_owned(),
        serde_json::json!({
            "post": {
                "parameters": [{
                    "in": "path",
                    "name": "workspaceId",
                    "required": true,
                    "schema": {"pattern": UUID_V7_PATTERN, "type": "string"},
                }],
                "requestBody": {
                    "content": {"application/json": {"schema": {"$ref": format!("{schema}request")}}},
                    "required": true,
                },
                "responses": {
                    "202": {
                        "content": {"application/json": {"schema": {"$ref": format!("{schema}receipt")}}},
                        "description": "Editor action accepted",
                    },
                    "400": error(),
                    "401": error(),
                    "403": error(),
                    "404": error(),
                    "409": error(),
                    "503": error(),
                },
                "security": [{"sessionAuth": []}],
            },
        }),
    );
}
