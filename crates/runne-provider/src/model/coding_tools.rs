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
