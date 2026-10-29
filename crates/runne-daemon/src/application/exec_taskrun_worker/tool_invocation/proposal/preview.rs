use super::*;
pub(super) fn summary(
    worker: &crate::application::exec_taskrun_worker::DaemonAutomaticTaskRuns,
    workspace_id: runne_domain::id::WorkspaceId,
    binding: &ToolInvocationBindingV1,
) -> Result<String, ()> {
    if binding.environment_id != crate::safe_tool_helper::coding_arguments::ENVIRONMENT {
        return Ok(format!(
            "Approve {} for workspace file {}",
            binding.tool_name, binding.target_name
        ));
    }
    let args: serde_json::Value =
        serde_json::from_slice(&binding.canonical_arguments).map_err(|_| ())?;
    let parsed = crate::safe_tool_helper::coding_arguments::parse(&binding.tool_name, &args)?;
    let mut preview = serde_json::json!({"operation":binding.tool_name,"arguments":args});
    if binding.tool_name == "workspace.command.run" {
        preview["workspace_permissions"] = serde_json::json!(["read", "create", "write", "delete"]);
        preview["network"] = serde_json::json!("none");
    }
    if matches!(
        binding.tool_name.as_str(),
        "workspace.file.replace" | "workspace.file.create_new"
    ) {
        let new = std::str::from_utf8(&parsed.content).map_err(|_| ())?;
        preview["new_text"] = serde_json::json!(new);
        if binding.tool_name == "workspace.file.replace" {
            let old = worker
                .root_admission
                .with_local_command_root(workspace_id, |root, _, _, _, _, _| {
                    let files = root.open_linux_command_workspace(std::path::Path::new("."))?;
                    crate::safe_tool_helper::coding_fs::bounded_read(
                        files.workspace(),
                        &parsed.path,
                    )
                    .map_err(|_| runne_platform_desktop::RootHandleBrokerError::Rejected)
                })
                .map_err(|_| ())?;
            if parsed.expected_sha256.as_deref() != Some(hex::encode(Sha256::digest(&old)).as_str())
            {
                return Err(());
            }
            preview["old_text"] = serde_json::json!(std::str::from_utf8(&old).map_err(|_| ())?);
        }
        preview["arguments"]
            .as_object_mut()
            .ok_or(())?
            .remove("content_base64");
    }
    let summary = serde_json::to_string(&preview).map_err(|_| ())?;
    // The current approval DTO is bounded to 4096 bytes. Never truncate the
    // exact command or diff the owner must approve.
    if summary.len() > 4096 {
        return Err(());
    }
    worker
        .provider
        .as_ref()
        .ok_or(())?
        .validate_tool_preview(summary.as_bytes())
        .map_err(|_| ())?;
    Ok(summary)
}
