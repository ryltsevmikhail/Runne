#[test]
fn excluded_or_wrong_snapshot_tools_cannot_mint_dispatch_authority() {
    let published = published();
    let active = binding(1, *published.discovery_digest());
    let excluded = ToolRef::new(
        ToolId::new("mcp::fixture-server::excluded").unwrap(),
        gocode_tools::ToolVersion::new("1.0.0").unwrap(),
    );
    assert!(
        published
            .issue_dispatch(
                &active,
                &excluded,
                McpInvocationId::new("excluded").unwrap(),
                json!({}),
            )
            .is_err()
    );
    assert!(
        published
            .issue_dispatch(
                &binding(1, [9; 32]),
                &published.snapshot().tool_refs()[0],
                McpInvocationId::new("wrong-snapshot").unwrap(),
                json!({}),
            )
            .is_err()
    );
}
