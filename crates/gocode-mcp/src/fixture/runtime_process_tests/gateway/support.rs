pub(super) fn next_binding(binding: &crate::McpDispatchBinding) -> crate::McpDispatchBinding {
    crate::McpDispatchBinding::new(
        binding.server_id().clone(),
        crate::McpRuntimeInstanceId::new("runtime-1").unwrap(),
        crate::McpConnectionId::new(binding.connection_id()).unwrap(),
        crate::McpSessionId::new("session-1").unwrap(),
        binding.generation() + 1,
        [9; 32],
    )
    .unwrap()
}
