#[test]
fn descriptor_constructors_preserve_protocol_default_and_allow_explicit_process_class() {
    let protocol = McpToolDescriptor::new("protocol", "1.0.0", json!({"type":"object"}))
        .unwrap();
    let process = McpToolDescriptor::new_with_execution_class(
        "process",
        "1.0.0",
        json!({"type":"object"}),
        McpToolExecutionClass::ProcessBacked,
    )
    .unwrap();

    assert_eq!(protocol.execution_class(), McpToolExecutionClass::ProtocolOnly);
    assert_eq!(process.execution_class(), McpToolExecutionClass::ProcessBacked);
}
