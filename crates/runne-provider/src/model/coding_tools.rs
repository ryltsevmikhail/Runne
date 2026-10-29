/// Full coding inventory is opt-in; legacy profiles retain their exact two declarations.
impl ProviderToolDeclarationV1 {
    /// Returns the explicit six-tool coding profile inventory; no profile opts in implicitly.
    pub fn coding_agent_v1() -> Vec<Self> {
        use ProviderToolNameV1::*;
        [
            WorkspaceFileRead,
            WorkspaceFileCreateNew,
            WorkspaceFilesList,
            WorkspaceFilesSearch,
            WorkspaceFileReplace,
            WorkspaceCommandRun,
        ]
        .into_iter()
        .map(Self::for_name)
        .collect()
    }

    /// Returns the inventory this execution node can actually enforce.
    ///
    /// macOS has no verified containment for arbitrary commands yet, so the
    /// command tool is not declared there. File tools remain bounded by the
    /// native helper.
    pub fn coding_agent_current_platform() -> Vec<Self> {
        let mut tools = Self::coding_agent_v1();
        if cfg!(target_os = "macos") {
            tools.retain(|tool| tool.name() != ProviderToolNameV1::WorkspaceCommandRun);
        }
        tools
    }
}

fn coding_tool_parameters(name: ProviderToolNameV1) -> Value {
    let path = serde_json::json!({"type":"string","minLength":1,"maxLength":255});
    let (properties, required) = match name {
        ProviderToolNameV1::WorkspaceFilesList => (
            serde_json::json!({"path":path,"limit":{"type":"integer","minimum":1,"maximum":200}}),
            serde_json::json!(["path", "limit"]),
        ),
        ProviderToolNameV1::WorkspaceFilesSearch => (
            serde_json::json!({"path":path,"query":{"type":"string","minLength":1,"maxLength":256},"limit":{"type":"integer","minimum":1,"maximum":100}}),
            serde_json::json!(["path", "query", "limit"]),
        ),
        ProviderToolNameV1::WorkspaceFileReplace => (
            serde_json::json!({"path":path,"expected_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},"content_base64":{"type":"string","maxLength":8192}}),
            serde_json::json!(["path", "expected_sha256", "content_base64"]),
        ),
        ProviderToolNameV1::WorkspaceCommandRun => (
            serde_json::json!({"cwd":path,"argv":{"type":"array","minItems":1,"maxItems":64,"items":{"type":"string","maxLength":1024}},"timeout_ms":{"type":"integer","minimum":1,"maximum":120000}}),
            serde_json::json!(["cwd", "argv", "timeout_ms"]),
        ),
        _ => unreachable!("legacy schemas stay in the legacy declaration"),
    };
    serde_json::json!({"type":"object","properties":properties,"required":required,"additionalProperties":false})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_platform_inventory_matches_enforceable_tools() {
        let tools = ProviderToolDeclarationV1::coding_agent_current_platform();
        let has_command = tools
            .iter()
            .any(|tool| tool.name() == ProviderToolNameV1::WorkspaceCommandRun);
        assert_eq!(has_command, !cfg!(target_os = "macos"));
        assert_eq!(tools.len(), if cfg!(target_os = "macos") { 5 } else { 6 });
    }
}
