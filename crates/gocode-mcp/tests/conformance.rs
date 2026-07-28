use gocode_mcp::{
    FixtureMcpAdapter, McpAdapterError, McpCallDisposition, McpCapabilities, McpClientPort,
    McpDiscoveryPage, McpRequestId, McpServerId, McpToolDescriptor,
};
use serde_json::json;

fn assert_client_port(_: &mut dyn McpClientPort) {}

fn adapter() -> FixtureMcpAdapter {
    FixtureMcpAdapter::new(
        McpServerId::new("fixture-server").unwrap(),
        "2025-11-25",
        McpCapabilities::new(true, true, true),
        vec![
            McpDiscoveryPage::new(
                None,
                vec![McpToolDescriptor::new("read", "1.0.0", json!({"type": "object"})).unwrap()],
                Some("page-2".into()),
            )
            .unwrap(),
            McpDiscoveryPage::new(
                Some("page-2".into()),
                vec![McpToolDescriptor::new("write", "1.0.0", json!({"type": "object"})).unwrap()],
                None,
            )
            .unwrap(),
        ],
    )
    .unwrap()
}

#[test]
fn stable_initialize_pagination_call_notification_cancel_and_close_conform() {
    let mut adapter = adapter();
    assert_client_port(&mut adapter);
    assert!(
        adapter
            .initialize("2025-11-25", McpCapabilities::new(true, true, true))
            .is_ok()
    );
    let snapshot = adapter.discover_all().unwrap();
    assert_eq!(
        snapshot
            .tools()
            .iter()
            .map(|tool| tool.name())
            .collect::<Vec<_>>(),
        ["read", "write"]
    );
    assert_eq!(
        adapter
            .call(
                McpRequestId::Number(1),
                "read",
                json!({"path": "README.md"}),
            )
            .unwrap(),
        McpCallDisposition::Completed
    );
    assert!(adapter.notify("progress", json!({"value": 1})).is_ok());
    assert!(adapter.cancel(&McpRequestId::Number(1)).is_ok());
    assert!(adapter.cancel(&McpRequestId::Number(1)).is_ok());
    assert!(adapter.close().is_ok());
    assert_eq!(
        adapter.notify("late", json!({})),
        Err(McpAdapterError::Closed)
    );
}

#[test]
fn wrong_version_capability_and_cursor_fail_closed() {
    let mut adapter = adapter();
    assert_eq!(
        adapter.initialize("2024-11-05", McpCapabilities::new(true, true, true)),
        Err(McpAdapterError::UnsupportedProtocol)
    );
    assert_eq!(
        adapter.initialize("2025-11-25", McpCapabilities::new(true, false, true)),
        Err(McpAdapterError::CapabilityMismatch)
    );
    assert!(
        adapter
            .initialize("2025-11-25", McpCapabilities::new(true, true, true))
            .is_ok()
    );
    assert_eq!(
        adapter.discovery_page(Some("forged")),
        Err(McpAdapterError::CursorMismatch)
    );
}
