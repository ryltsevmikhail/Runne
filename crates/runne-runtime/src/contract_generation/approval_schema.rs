fn approval_schema() -> Value {
    json!({
        "$id": "gocode://schemas/approval-v1",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Approval API V1",
        "type": "object",
        "$defs": {
            "approval": closed_object(json!({
                "approvalId": uuid_v7_schema(), "taskRunId": uuid_v7_schema(), "attemptId": {"anyOf": [uuid_v7_schema(), {"type": "null"}]}, "invocationId": uuid_v7_schema(),
                "action": {"type": "string", "minLength": 1, "maxLength": 4096}, "resource": {"type": "string", "minLength": 1, "maxLength": 4096}, "actionDigest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "policyRevision": {"type": "integer", "minimum": 1}, "requestVersion": {"type": "integer", "minimum": 1}, "expiresAt": {"type": "integer", "minimum": 1}, "riskSummary": {"type": "string", "minLength": 1, "maxLength": 4096},
                "state": {"enum": ["pending", "approved", "denied", "expired", "cancelled"], "type": "string"}
            }), &["approvalId", "taskRunId", "attemptId", "invocationId", "action", "resource", "actionDigest", "policyRevision", "requestVersion", "expiresAt", "riskSummary", "state"]),
            "list": closed_object(json!({"items": {"type": "array", "items": {"$ref": "#/$defs/approval"}, "maxItems": 1024}}), &["items"]),
            "decisionRequest": closed_object(json!({"expectedVersion": {"type": "integer", "minimum": 1}, "decision": {"enum": ["approve", "deny"], "type": "string"}, "actionDigest": {"type": "string", "pattern": "^[0-9a-f]{64}$"}, "policyRevision": {"type": "integer", "minimum": 1}, "rendererGeneration": {"type": "integer", "minimum": 1}}), &["expectedVersion", "decision", "actionDigest", "policyRevision", "rendererGeneration"]),
            "decisionAcknowledgement": closed_object(json!({"approvalId": uuid_v7_schema(), "taskRunId": uuid_v7_schema(), "newVersion": {"type": "integer", "minimum": 1}, "state": {"enum": ["approved", "denied", "expired", "cancelled"], "type": "string"}}), &["approvalId", "taskRunId", "newVersion", "state"])
        }
    })
}
