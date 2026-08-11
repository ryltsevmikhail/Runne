pub(super) fn project_workspace_schema() -> Value {
    let id = || json!({"maxLength": 36, "pattern": UUID_V7_PATTERN, "type": "string"});
    let version = || positive_integer_schema();
    let name = || json!({
        "maxLength": 256,
        "minLength": 1,
        "pattern": "^[^\u{0000}-\u{001f}\u{007f}-\u{009f}\u{00ad}\u{0600}-\u{0605}\u{061c}\u{06dd}\u{070f}\u{0890}-\u{0891}\u{08e2}\u{180e}\u{200b}-\u{200f}\u{202a}-\u{202e}\u{2060}-\u{2064}\u{2066}-\u{206f}\u{feff}\u{fff9}-\u{fffb}\u{110bd}\u{110cd}\u{13430}-\u{1343f}\u{1bca0}-\u{1bca3}\u{1d173}-\u{1d17a}\u{e0001}\u{e0020}-\u{e007f}]*$",
        "type": "string",
        "x-gocode-displayNamePolicy": "project-workspace-v1",
        "x-gocode-maxUtf8Bytes": 256,
    });
    let project = || closed_object(json!({"projectId": id(), "displayName": name(), "version": version(), "archived": {"type": "boolean"}}), &["projectId", "displayName", "version", "archived"]);
    let workspace = || closed_object(json!({"workspaceId": id(), "projectId": id(), "displayName": name(), "version": version(), "open": {"type": "boolean"}}), &["workspaceId", "projectId", "displayName", "version", "open"]);
    let cursor = |prefix: &str, hex_length: usize| json!({
        "maxLength": prefix.len() + 1 + hex_length,
        "minLength": prefix.len() + 1 + hex_length,
        "pattern": format!("^{prefix}\\.[0-9a-f]{{{hex_length}}}$"),
        "type": "string",
    });
    let root_admission = json!({
        "anyOf": [
            {"pattern": "^gocode-root-admission-v2\\.(?:[A-Za-z0-9_-]{4})+$"},
            {"pattern": "^gocode-root-admission-v2\\.(?:[A-Za-z0-9_-]{4})*[A-Za-z0-9_-][AQgw]$"},
            {"pattern": "^gocode-root-admission-v2\\.(?:[A-Za-z0-9_-]{4})*[A-Za-z0-9_-]{2}[AEIMQUYcgkosw048]$"}
        ],
        "maxLength": 5487,
        "minLength": 27,
        "type": "string",
        "x-gocode-maxUtf8Bytes": 5487,
    });
    let defs = json!({
        "project": project(), "workspace": workspace(),
        "projectCreate": closed_object(json!({"projectId": id(), "displayName": name()}), &["projectId", "displayName"]),
        "workspaceCreate": closed_object(json!({"workspaceId": id(), "displayName": name()}), &["workspaceId", "displayName"]),
        "existing": closed_object(json!({"expectedVersion": version()}), &["expectedVersion"]),
        "rootBind": closed_object(json!({"expectedVersion": version(), "rootAdmission": root_admission}), &["expectedVersion", "rootAdmission"]),
        "projectAck": closed_object(json!({"projectId": id(), "newVersion": version()}), &["projectId", "newVersion"]),
        "workspaceAck": closed_object(json!({"workspaceId": id(), "newVersion": version()}), &["workspaceId", "newVersion"]),
        "projectPage": closed_object(json!({"items": {"items": {"$ref": "#/$defs/project"}, "maxItems": 100, "type": "array"}, "nextCursor": {"anyOf": [cursor("gocode-project-page-v1", 96), {"type": "null"}]}}), &["items", "nextCursor"]),
        "workspacePage": closed_object(json!({"items": {"items": {"$ref": "#/$defs/workspace"}, "maxItems": 100, "type": "array"}, "nextCursor": {"anyOf": [cursor("gocode-workspace-page-v1", 128), {"type": "null"}]}}), &["items", "nextCursor"]),
        "error": closed_object(json!({"code": {"maxLength": 128, "type": "string"}, "requestId": id()}), &["code", "requestId"]),
    });
    let mut schema = closed_object(json!({"project": {"$ref": "#/$defs/project"}, "workspace": {"$ref": "#/$defs/workspace"}, "projectPage": {"$ref": "#/$defs/projectPage"}, "workspacePage": {"$ref": "#/$defs/workspacePage"}, "rootBind": {"$ref": "#/$defs/rootBind"}}), &["project", "workspace", "projectPage", "workspacePage", "rootBind"]);
    let object = schema.as_object_mut().expect("closed object");
    object.insert("$defs".into(), defs); object.insert("$id".into(), json!("gocode://schemas/project-workspace-v1")); object.insert("$schema".into(), json!(DRAFT_2020_12)); object.insert("title".into(), json!("Project Workspace V1"));
    schema
}

pub(super) fn project_workspace_golden() -> Value {
    json!({"project": {"projectId": "018f2e3a-7000-7000-8000-000000000201", "displayName": "Project", "version": 1, "archived": false}, "workspace": {"workspaceId": "018f2e3a-7000-7000-8000-000000000202", "projectId": "018f2e3a-7000-7000-8000-000000000201", "displayName": "Workspace", "version": 1, "open": false}, "projectPage": {"items": [], "nextCursor": null}, "workspacePage": {"items": [], "nextCursor": null}, "rootBind": {"expectedVersion": 1, "rootAdmission": "gocode-root-admission-v2.AA"}})
}
