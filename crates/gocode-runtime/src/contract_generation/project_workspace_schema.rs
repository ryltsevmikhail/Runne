pub(super) fn project_workspace_schema() -> Value {
    let encoded_len = (gocode_api::ROOT_HANDLE_ADMISSION_V3_BYTES * 4).div_ceil(3);
    let full_groups = (encoded_len - 2) / 4;
    let root_admission_pattern = format!(
        "^gocode-root-admission-v3\\.(?:[A-Za-z0-9_-]{{4}}){{{full_groups}}}[A-Za-z0-9_-]{{1}}[AQgw]$"
    );
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
    let cursor = |length: usize, pattern: &str| json!({
        "maxLength": length,
        "minLength": length,
        "pattern": pattern,
        "type": "string",
    });
    let root_admission = json!({
        "maxLength": gocode_api::MAX_ROOT_HANDLE_ADMISSION_TOKEN_BYTES,
        "minLength": gocode_api::MAX_ROOT_HANDLE_ADMISSION_TOKEN_BYTES,
        "pattern": root_admission_pattern,
        "type": "string",
        "x-gocode-maxUtf8Bytes": gocode_api::MAX_ROOT_HANDLE_ADMISSION_TOKEN_BYTES,
    });
    let defs = json!({
        "project": project(), "workspace": workspace(),
        "projectCreate": closed_object(json!({"projectId": id(), "displayName": name()}), &["projectId", "displayName"]),
        "workspaceCreate": closed_object(json!({"workspaceId": id(), "displayName": name()}), &["workspaceId", "displayName"]),
        "existing": closed_object(json!({"expectedVersion": version()}), &["expectedVersion"]),
        "rootBind": closed_object(json!({"expectedVersion": version(), "rootAdmission": root_admission}), &["expectedVersion", "rootAdmission"]),
        "projectAck": closed_object(json!({"projectId": id(), "newVersion": version()}), &["projectId", "newVersion"]),
        "workspaceAck": closed_object(json!({"workspaceId": id(), "newVersion": version()}), &["workspaceId", "newVersion"]),
        "projectPage": closed_object(json!({"items": {"items": {"$ref": "#/$defs/project"}, "maxItems": 100, "type": "array"}, "nextCursor": {"anyOf": [cursor(PROJECT_PAGE_CURSOR_LENGTH, PROJECT_PAGE_CURSOR_PATTERN), {"type": "null"}]}}), &["items", "nextCursor"]),
        "workspacePage": closed_object(json!({"items": {"items": {"$ref": "#/$defs/workspace"}, "maxItems": 100, "type": "array"}, "nextCursor": {"anyOf": [cursor(WORKSPACE_PAGE_CURSOR_LENGTH, WORKSPACE_PAGE_CURSOR_PATTERN), {"type": "null"}]}}), &["items", "nextCursor"]),
        "error": closed_object(json!({"code": {"maxLength": 128, "type": "string"}, "requestId": id()}), &["code", "requestId"]),
    });
    let mut schema = closed_object(json!({"project": {"$ref": "#/$defs/project"}, "workspace": {"$ref": "#/$defs/workspace"}, "projectPage": {"$ref": "#/$defs/projectPage"}, "workspacePage": {"$ref": "#/$defs/workspacePage"}, "rootBind": {"$ref": "#/$defs/rootBind"}}), &["project", "workspace", "projectPage", "workspacePage", "rootBind"]);
    let object = schema.as_object_mut().expect("closed object");
    object.insert("$defs".into(), defs); object.insert("$id".into(), json!("gocode://schemas/project-workspace-v2")); object.insert("$schema".into(), json!(DRAFT_2020_12)); object.insert("title".into(), json!("Project Workspace V2"));
    schema
}

pub(super) fn project_workspace_golden() -> Value {
    let root_admission = format!(
        "gocode-root-admission-v3.{}",
        "A".repeat((gocode_api::ROOT_HANDLE_ADMISSION_V3_BYTES * 4).div_ceil(3)),
    );
    json!({"project": {"projectId": "018f2e3a-7000-7000-8000-000000000201", "displayName": "Project", "version": 1, "archived": false}, "workspace": {"workspaceId": "018f2e3a-7000-7000-8000-000000000202", "projectId": "018f2e3a-7000-7000-8000-000000000201", "displayName": "Workspace", "version": 1, "open": false}, "projectPage": {"items": [], "nextCursor": null}, "workspacePage": {"items": [], "nextCursor": null}, "rootBind": {"expectedVersion": 1, "rootAdmission": root_admission}})
}
