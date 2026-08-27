fn approval_openapi(document: &mut Value) {
    let paths = document["paths"]
        .as_object_mut()
        .expect("OpenAPI paths object");
    let parameter =
        json!({"in": "path", "name": "approvalId", "required": true, "schema": uuid_v7_schema()});
    let list_response = json!({"200": {"content": {"application/json": {"schema": {"$ref": "schemas/approval-v1.schema.json#/$defs/list"}}}, "description": "Authorized approvals"}});
    let item_response = json!({"200": {"content": {"application/json": {"schema": {"$ref": "schemas/approval-v1.schema.json#/$defs/approval"}}}, "description": "Authorized approval"}});
    let decision_response = json!({"202": {"content": {"application/json": {"schema": {"$ref": "schemas/approval-v1.schema.json#/$defs/decisionAcknowledgement"}}}, "description": "Decision accepted"}});
    paths.insert(
        "/v1/approvals".into(),
        json!({"get": {"responses": list_response, "summary": "List pending approvals"}}),
    );
    paths.insert("/v1/approvals/{approvalId}".into(), json!({"get": {"parameters": [parameter.clone()], "responses": item_response, "summary": "Get one approval"}}));
    paths.insert("/v1/approvals/{approvalId}/decision".into(), json!({"post": {"parameters": [parameter], "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "schemas/approval-v1.schema.json#/$defs/decisionRequest"}}}}, "responses": decision_response, "summary": "Decide approval"}}));
}
