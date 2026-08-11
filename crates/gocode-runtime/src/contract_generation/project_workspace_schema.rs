pub(super) fn project_workspace_schema() -> Value {
    let id = || json!({"maxLength": 36, "pattern": UUID_V7_PATTERN, "type": "string"});
    let version = || positive_integer_schema();
    let name = || json!({"maxLength": 256, "minLength": 1, "type": "string", "x-gocode-maxUtf8Bytes": 256});
    let project = || closed_object(json!({"projectId": id(), "displayName": name(), "version": version(), "archived": {"type": "boolean"}}), &["projectId", "displayName", "version", "archived"]);
    let workspace = || closed_object(json!({"workspaceId": id(), "projectId": id(), "displayName": name(), "version": version(), "open": {"type": "boolean"}}), &["workspaceId", "projectId", "displayName", "version", "open"]);
    let cursor = |prefix: &str, length: usize| json!({"maxLength": length, "minLength": length, "pattern": format!("^{prefix}\\.(?:[0-9a-f]{{2}})+$"), "type": "string"});
    let defs = json!({
        "project": project(), "workspace": workspace(),
        "projectCreate": closed_object(json!({"projectId": id(), "displayName": name()}), &["projectId", "displayName"]),
        "workspaceCreate": closed_object(json!({"workspaceId": id(), "displayName": name()}), &["workspaceId", "displayName"]),
        "existing": closed_object(json!({"expectedVersion": version()}), &["expectedVersion"]),
        "rootBind": closed_object(json!({"expectedVersion": version(), "rootAdmission": {"maxLength": 5487, "minLength": 27, "pattern": "^gocode-root-admission-v2\\.[A-Za-z0-9_-]+$", "type": "string", "x-gocode-maxUtf8Bytes": 5487}}), &["expectedVersion", "rootAdmission"]),
        "projectAck": closed_object(json!({"projectId": id(), "newVersion": version()}), &["projectId", "newVersion"]),
        "workspaceAck": closed_object(json!({"workspaceId": id(), "newVersion": version()}), &["workspaceId", "newVersion"]),
        "projectPage": closed_object(json!({"items": {"items": {"$ref": "#/$defs/project"}, "maxItems": 100, "type": "array"}, "nextCursor": {"anyOf": [cursor("gocode-project-page-v1", 119), {"type": "null"}]}}), &["items", "nextCursor"]),
        "workspacePage": closed_object(json!({"items": {"items": {"$ref": "#/$defs/workspace"}, "maxItems": 100, "type": "array"}, "nextCursor": {"anyOf": [cursor("gocode-workspace-page-v1", 153), {"type": "null"}]}}), &["items", "nextCursor"]),
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
