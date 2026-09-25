fn provider_credentials_schema() -> Value {
    let credential = json!({
        "maxLength": 5462,
        "minLength": 2,
        "pattern": BASE64_URL_PATTERN,
        "type": "string",
    });
    let provider = enum_schema(&["openai", "deepseek"]);
    let status = enum_schema(&[
        "configured",
        "missing",
        "unsupported",
        "access_denied",
        "identity_mismatch",
        "unavailable",
    ]);
    let definitions = json!({
        "mutationAcknowledgement": closed_object(
            json!({"providerId": provider, "status": status}),
            &["providerId", "status"],
        ),
        "pairRequest": closed_object(json!({"credential": credential}), &["credential"]),
    });
    let mut schema = closed_object(json!({}), &[]);
    let object = schema.as_object_mut().expect("schema object");
    object.insert("$defs".to_owned(), definitions);
    object.insert("$id".to_owned(), json!("gocode://schemas/provider-credentials-v1"));
    object.insert("$schema".to_owned(), json!(DRAFT_2020_12));
    object.insert("title".to_owned(), json!("Provider Credential Control V1"));
    schema
}

fn provider_credentials_openapi(document: &mut Value) {
    let schema = "schemas/provider-credentials-v1.schema.json#/$defs/";
    let provider = json!({
        "in": "path",
        "name": "provider",
        "required": true,
        "schema": enum_schema(&["openai", "deepseek"]),
    });
    let error = || json!({"description": "Static redacted error response"});
    let responses = || json!({
        "202": {
            "content": {"application/json": {"schema": {"$ref": format!("{schema}mutationAcknowledgement")}}},
            "description": "Provider credential mutation accepted",
        },
        "400": error(),
        "401": error(),
        "403": error(),
        "409": error(),
        "503": error(),
    });
    document["paths"]["/v1/providers/{provider}/credential"] = json!({
        "delete": {
            "parameters": [provider.clone()],
            "responses": responses(),
            "security": [{"sessionAuth": []}],
        },
        "put": {
            "parameters": [provider],
            "requestBody": {
                "content": {"application/json": {"schema": {"$ref": format!("{schema}pairRequest")}}},
                "required": true,
            },
            "responses": responses(),
            "security": [{"sessionAuth": []}],
        },
    });
}
