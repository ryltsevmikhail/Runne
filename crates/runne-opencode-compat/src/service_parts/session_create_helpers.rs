/// Computes the deterministic, domain-separated SHA-256 request fingerprint.
pub fn fingerprint(input: &OpenCodeCreateInput) -> SessionCreateFingerprint {
    let mut hasher = Sha256::new();
    write_field(
        &mut hasher,
        b"runne-opencode-compat/session-create-fingerprint/v1",
    );
    write_optional_string(&mut hasher, input.title.as_deref());
    write_optional_string(&mut hasher, input.workspace_id.as_deref());
    SessionCreateFingerprint::from_bytes(hasher.finalize().into())
}

fn write_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn write_optional_string(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            write_field(hasher, value.as_bytes());
        }
        None => hasher.update([0]),
    }
}

fn validate_supported_fields(input: &OpenCodeCreateInput) -> Result<(), SessionCreateError> {
    for (field, present) in [
        ("parentID", input.parent_id.is_some()),
        ("agent", input.agent.is_some()),
        ("model", input.model.is_some()),
        ("metadata", input.metadata.is_some()),
        ("permission", input.permission.is_some()),
    ] {
        if present {
            return Err(SessionCreateError::UnsupportedField { field });
        }
    }
    Ok(())
}

fn build_session_info(
    key: &SessionBindingKey,
    context: &SessionBindingContext,
    output: &CreateConversationOutput,
    schema: &JSONSchema,
) -> Result<OpenCodeSessionInfo, SessionCreateError> {
    let mut value = serde_json::json!({
        "id": key.session_id.as_str(),
        "slug": key.session_id.as_str(),
        "projectID": context.response_seed.project_id,
        "directory": context.response_seed.directory,
        "title": context.title.as_deref().unwrap_or("Untitled"),
        "version": context.response_seed.version,
        "time": {
            "created": output.committed_at.as_i64(),
            "updated": output.committed_at.as_i64(),
        },
    });
    if let Some(path) = &context.response_seed.path {
        value["path"] = serde_json::Value::String(path.clone());
    }
    if let Some(workspace_id) = &context.response_seed.workspace_id {
        value["workspaceID"] = serde_json::Value::String(workspace_id.clone());
    }
    OpenCodeSessionInfo::from_json(value, schema).map_err(SessionCreateError::Validation)
}
