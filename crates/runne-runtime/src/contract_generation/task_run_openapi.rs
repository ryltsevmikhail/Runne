fn task_run_openapi(document: &mut Value) {
    let paths = document
        .get_mut("paths")
        .and_then(Value::as_object_mut)
        .expect("OpenAPI document has paths object");
    paths.insert(
        "/v1/task-runs/{taskRunId}".to_owned(),
        json!({
            "get": {
                "parameters": [{
                    "in": "path",
                    "name": "taskRunId",
                    "required": true,
                    "schema": uuid_v7_schema(),
                }],
                "security": [{"sessionAuth": []}],
                "responses": {
                    "200": {
                        "content": {"application/json": {"schema": {"$ref": "schemas/task-run-v1.schema.json"}}},
                        "description": "Canonical response",
                    },
                    "400": task_run_error_response(),
                    "401": task_run_error_response(),
                    "404": task_run_error_response(),
                    "409": task_run_error_response(),
                    "503": task_run_error_response(),
                },
            },
        }),
    );
}

fn task_run_error_response() -> Value {
    json!({
        "description": "Static redacted error response",
        "headers": {
            "Cache-Control": {
                "description": "Responses are never stored",
                "schema": {"const": "no-store", "type": "string"},
            },
        },
    })
}
