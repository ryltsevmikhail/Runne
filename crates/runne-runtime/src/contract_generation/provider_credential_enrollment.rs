fn provider_credential_enrollment_schema() -> Value {
    let provider = enum_schema(&["openai", "deepseek"]);
    let positive = positive_integer_schema();
    let opaque = json!({"maxLength": 256, "minLength": 1, "pattern": "^[^\\u0000-\\u001f\\u007f]+$", "type": "string"});
    let handle = json!({"pattern": "^[0-9a-f]{96}$", "type": "string"});
    let error = closed_object(
        json!({"code": string_schema(128), "requestId": uuid_v7_schema()}),
        &["code", "requestId"],
    );
    let begin = closed_object(
        json!({
            "action": enum_schema(&["pair", "revoke", "migrate_legacy"]),
            "commandIdentity": uuid_v7_schema(), "expectedLifecycleRevision": positive.clone(),
            "idempotencyKey": opaque.clone(), "nativeIntentId": opaque.clone(), "provider": provider.clone(),
        }),
        &[
            "action",
            "provider",
            "expectedLifecycleRevision",
            "commandIdentity",
            "idempotencyKey",
            "nativeIntentId",
        ],
    );
    let resume = closed_object(json!({"operationId": handle.clone()}), &["operationId"]);
    let verify = closed_object(
        json!({
            "commandIdentity": uuid_v7_schema(), "expectedLifecycleRevision": positive.clone(),
            "nativeIntentId": opaque, "provider": provider.clone(), "verificationKind": enum_schema(&["local", "remote"]),
        }),
        &[
            "provider",
            "expectedLifecycleRevision",
            "verificationKind",
            "commandIdentity",
            "nativeIntentId",
        ],
    );
    let operation = operation_snapshot_schema(&provider, &positive, &handle);
    let status = safe_snapshot_schema(&provider, &positive);
    let mut schema = closed_object(
        json!({
            "beginRequest": {"$ref": "#/$defs/beginRequest"},
            "operationResponse": {"$ref": "#/$defs/operationResponse"},
            "resumeRequest": {"$ref": "#/$defs/resumeRequest"},
            "statusResponse": {"$ref": "#/$defs/statusResponse"},
            "verifyRequest": {"$ref": "#/$defs/verifyRequest"},
        }),
        &[
            "beginRequest",
            "operationResponse",
            "resumeRequest",
            "statusResponse",
            "verifyRequest",
        ],
    );
    let object = schema.as_object_mut().expect("closed enrollment schema");
    object.insert(
        "$defs".to_owned(),
        json!({
            "beginRequest": begin, "error": error, "operationResponse": operation,
            "resumeRequest": resume, "statusResponse": status, "verifyRequest": verify,
        }),
    );
    object.insert(
        "$id".to_owned(),
        json!("gocode://schemas/provider-credential-enrollment-v2"),
    );
    object.insert("$schema".to_owned(), json!(DRAFT_2020_12));
    object.insert(
        "title".to_owned(),
        json!("Protected Provider Credential Enrollment V2"),
    );
    schema
}

fn operation_snapshot_schema(provider: &Value, positive: &Value, handle: &Value) -> Value {
    let mut schema = closed_object(
        json!({
            "brokerRendezvousId": {"oneOf": [json!({"maxLength": 256, "minLength": 1, "pattern": "^[^\\u0000-\\u001f\\u007f]+$", "type": "string"}), json!({"type": "null"})]},
            "cleanupPending": {"type": "boolean"}, "lastDisposition": {"oneOf": [enum_schema(&["completed", "access_denied", "unsupported", "unavailable", "conflict", "invalid_request", "invariant_failure"]), json!({"type": "null"})]},
            "lifecycleRevision": positive.clone(), "operationId": handle.clone(),
            "operationKind": enum_schema(&["pair", "revoke", "migrate_legacy", "verify_local", "verify_remote"]),
            "providerId": provider.clone(), "readinessRevision": positive.clone(),
            "state": enum_schema(&["prepared", "claimed", "native_effect_observed", "readback_verified", "completed", "failed", "expired", "cancelled", "tombstoned"]),
        }),
        &[
            "operationId",
            "brokerRendezvousId",
            "providerId",
            "operationKind",
            "state",
            "lifecycleRevision",
            "readinessRevision",
            "cleanupPending",
            "lastDisposition",
        ],
    );
    schema.as_object_mut().expect("operation schema").insert("allOf".to_owned(), json!([
        {"if": {"properties": {"operationKind": {"enum": ["pair", "revoke", "migrate_legacy"]}}}, "then": {"properties": {"brokerRendezvousId": {"not": {"type": "null"}}}}},
        {"if": {"properties": {"operationKind": {"enum": ["verify_local", "verify_remote"]}}}, "then": {"properties": {"brokerRendezvousId": {"type": "null"}}}},
    ]));
    schema
}

fn safe_snapshot_schema(provider: &Value, positive: &Value) -> Value {
    closed_object(
        json!({
            "cleanupPending": {"type": "boolean"},
            "credentialState": enum_schema(&["configured", "missing", "access_denied", "unsupported", "unavailable"]),
            "lastDisposition": {"oneOf": [enum_schema(&["completed", "access_denied", "unsupported", "unavailable", "conflict", "invalid_request", "invariant_failure"]), json!({"type": "null"})]},
            "lifecycleRevision": positive.clone(), "observedAt": {"maximum": i64::MAX, "minimum": 0, "type": "integer"},
            "pendingOperation": {"oneOf": [enum_schema(&["pairing", "rotating", "revoking", "reconciling", "verifying"]), json!({"type": "null"})]},
            "providerId": provider.clone(), "readiness": enum_schema(&["ready", "missing", "stale", "unavailable", "unsupported", "access_denied", "conflict", "invariant_failure"]),
            "readinessRevision": positive.clone(), "verificationRevision": {"maximum": u64::MAX, "minimum": 0, "type": "integer"},
            "verificationState": enum_schema(&["not_verified", "local_verified", "remote_verified", "failed", "unsupported", "unavailable", "access_denied", "stale"]),
        }),
        &[
            "providerId",
            "credentialState",
            "readiness",
            "lifecycleRevision",
            "readinessRevision",
            "observedAt",
            "verificationState",
            "verificationRevision",
            "pendingOperation",
            "cleanupPending",
            "lastDisposition",
        ],
    )
}

fn provider_credential_enrollment_golden() -> Value {
    json!({
        "beginRequest": {"action": "pair", "provider": "openai", "expectedLifecycleRevision": 7, "commandIdentity": "018f0c4e-7b9a-7cc2-8f0a-123456789abc", "idempotencyKey": "pair-openai-7", "nativeIntentId": "intent-openai-7"},
        "operationResponse": {"operationId": "01".repeat(48), "brokerRendezvousId": "broker-openai-7", "providerId": "openai", "operationKind": "pair", "state": "prepared", "lifecycleRevision": 7, "readinessRevision": 7, "cleanupPending": false, "lastDisposition": null},
        "resumeRequest": {"operationId": "01".repeat(48)},
        "statusResponse": {"providerId": "openai", "credentialState": "configured", "readiness": "ready", "lifecycleRevision": 7, "readinessRevision": 7, "observedAt": 1, "verificationState": "not_verified", "verificationRevision": 0, "pendingOperation": null, "cleanupPending": false, "lastDisposition": "completed"},
        "verifyRequest": {"provider": "openai", "expectedLifecycleRevision": 7, "verificationKind": "remote", "commandIdentity": "018f0c4e-7b9a-7cc2-8f0a-123456789abc", "nativeIntentId": "verify-openai-7"},
    })
}

fn provider_credential_enrollment_openapi(document: &mut Value) {
    let schema = "schemas/provider-credential-enrollment-v2.schema.json#/$defs/";
    let error = || json!({"content": {"application/json": {"schema": {"$ref": format!("{schema}error")}}}, "description": "Canonical redacted error"});
    let responses = |success: &str, definition: &str, description: &str| {
        json!({
            success: {"content": {"application/json": {"schema": {"$ref": format!("{schema}{definition}")}}}, "description": description},
            "400": error(), "401": error(), "403": error(), "409": error(), "500": error(), "503": error(),
        })
    };
    let secured = json!({"sessionAuth": []});
    document["paths"]["/v2/provider-credential-enrollment"] = json!({"post": {
        "requestBody": {"content": {"application/json": {"schema": {"$ref": format!("{schema}beginRequest")}}}, "required": true},
        "responses": responses("202", "operationResponse", "Enrollment operation accepted"), "security": [secured.clone()],
    }});
    document["paths"]["/v2/provider-credential-enrollment/resume"] = json!({"post": {
        "requestBody": {"content": {"application/json": {"schema": {"$ref": format!("{schema}resumeRequest")}}}, "required": true},
        "responses": responses("200", "operationResponse", "Enrollment operation resumed"), "security": [secured.clone()],
    }});
    document["paths"]["/v2/providers/{provider}/credential-enrollment"] = json!({"get": {
        "parameters": [{"in": "path", "name": "provider", "required": true, "schema": enum_schema(&["openai", "deepseek"])}],
        "responses": responses("200", "statusResponse", "Current provider credential projection"), "security": [secured.clone()],
    }});
    document["paths"]["/v2/provider-credential-enrollment/verify"] = json!({"post": {
        "requestBody": {"content": {"application/json": {"schema": {"$ref": format!("{schema}verifyRequest")}}}, "required": true},
        "responses": responses("202", "operationResponse", "Credential verification accepted"), "security": [secured],
    }});
}
