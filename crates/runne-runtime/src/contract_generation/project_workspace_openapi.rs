fn project_workspace_openapi(document: &mut Value) {
    let schema = "schemas/project-workspace-v2.schema.json#/$defs/";
    let response = |name: &str| json!({"description": "Canonical response", "headers": {"X-Request-Id": {"required": true, "schema": {"maxLength": 36, "pattern": UUID_V7_PATTERN, "type": "string"}}}, "content": {"application/json": {"schema": {"$ref": format!("{schema}{name}")}}}});
    let id = |name: &str| json!({"in": "path", "name": name, "required": true, "schema": {"maxLength": 36, "pattern": UUID_V7_PATTERN, "type": "string"}});
    let page = |length: usize, pattern: &str| json!([
        {"in": "query", "name": "limit", "schema": {"default": 50, "maximum": 100, "minimum": 1, "type": "integer"}},
        {"in": "query", "name": "cursor", "schema": {
            "maxLength": length,
            "minLength": length,
            "pattern": pattern,
            "type": "string"
        }}
    ]);
    let command = || json!([
        {"in": "header", "name": "X-Command-Id", "required": true, "schema": {"maxLength": 36, "pattern": UUID_V7_PATTERN, "type": "string"}},
        {"in": "header", "name": "Idempotency-Key", "required": true, "schema": {
            "maxLength": 256, "minLength": 1, "pattern": "^[\\u0020-\\u007e]+$",
            "type": "string", "x-gocode-maxUtf8Bytes": 256
        }}
    ]);
    let operation = |request: &str, success: &str| json!({"security": [{"sessionAuth": []}], "parameters": command(), "requestBody": {"required": true, "x-gocode-maxBodyBytes": 16384, "content": {"application/json": {"schema": {"$ref": format!("{schema}{request}")}}}}, "responses": {"202": response(success), "400": response("error"), "401": response("error"), "404": response("error"), "405": response("error"), "409": response("error"), "413": response("error"), "500": response("error"), "503": response("error")}});
    let read = |success: &str, parameters: Value| json!({"security": [{"sessionAuth": []}], "parameters": parameters, "responses": {"200": response(success), "400": response("error"), "401": response("error"), "404": response("error"), "405": response("error"), "409": response("error"), "413": response("error"), "500": response("error"), "503": response("error")}});
    let paths = document["paths"].as_object_mut().expect("OpenAPI paths object");
    paths.insert("/v1/projects".into(), json!({"get": read("projectPage", page(PROJECT_PAGE_CURSOR_LENGTH, PROJECT_PAGE_CURSOR_PATTERN)), "post": operation("projectCreate", "projectAck")}));
    paths.insert("/v1/projects/{projectId}".into(), json!({"get": read("project", json!([])), "delete": operation("existing", "projectAck"), "parameters": [id("projectId")]}));
    for name in ["archive", "restore"] { paths.insert(format!("/v1/projects/{{projectId}}/{name}"), json!({"post": operation("existing", "projectAck"), "parameters": [id("projectId")]})); }
    paths.insert("/v1/projects/{projectId}/workspaces".into(), json!({"get": read("workspacePage", page(WORKSPACE_PAGE_CURSOR_LENGTH, WORKSPACE_PAGE_CURSOR_PATTERN)), "post": operation("workspaceCreate", "workspaceAck"), "parameters": [id("projectId")]}));
    paths.insert("/v1/workspaces/{workspaceId}".into(), json!({"get": read("workspace", json!([])), "parameters": [id("workspaceId")]}));
    paths.insert("/v1/workspaces/{workspaceId}/open".into(), json!({"post": operation("existing", "workspaceAck"), "parameters": [id("workspaceId")]}));
    paths.insert("/v1/workspaces/{workspaceId}/root-bindings".into(), json!({"post": operation("rootBind", "workspaceAck"), "parameters": [id("workspaceId")]}));
}
