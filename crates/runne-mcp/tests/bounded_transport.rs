use runne_mcp::{
    BoundedMcpTransport, McpSdkIntegrationEvidence, McpSdkIntegrationProfileId,
    McpSdkIntegrationProfileRef, McpTransportError, McpTransportLimits, McpTransportPort,
    PRODUCTION_MCP_SDK_ENABLED,
};

const _: () = assert!(!PRODUCTION_MCP_SDK_ENABLED);

struct NoIo;
impl McpTransportPort for NoIo {
    fn send(&mut self, _: &[u8]) -> Result<(), McpTransportError> {
        Ok(())
    }
    fn receive(&mut self, _: &mut [u8]) -> Result<usize, McpTransportError> {
        Err(McpTransportError::Unavailable)
    }
}

fn limits() -> McpTransportLimits {
    McpTransportLimits {
        max_frame_bytes: 128,
        max_buffer_bytes: 512,
        max_nesting: 2,
        max_collection_items: 3,
        max_string_bytes: 16,
        max_in_flight: 1,
        max_in_flight_notifications: 1,
        max_frames_per_window: 3,
    }
}

#[test]
fn exact_byte_semantic_rate_and_inflight_bounds_fail_closed() {
    let mut transport = BoundedMcpTransport::new(NoIo, limits());
    assert_eq!(
        transport.decode_frame(&[b'x'; 129]),
        Err(McpTransportError::ByteLimit)
    );
    assert!(transport.claim_request().is_ok());
    assert_eq!(
        transport.claim_request(),
        Err(McpTransportError::InFlightLimit)
    );
    transport.complete_request();
    assert!(transport.claim_notification().is_ok());
    assert_eq!(
        transport.claim_notification(),
        Err(McpTransportError::InFlightLimit)
    );
    transport.complete_notification();
    assert_eq!(
        transport.decode_frame(br#"{"jsonrpc":"2.0","method":"x","params":{"a":{"b":1}}}"#),
        Err(McpTransportError::SemanticLimit)
    );
    transport.reset_admission_window();
    assert_eq!(
        transport.decode_frame(br#"{"jsonrpc":"2.0","method":"x","params":[1,2,3,4]}"#),
        Err(McpTransportError::SemanticLimit)
    );
    transport.reset_admission_window();
    assert_eq!(
        transport.decode_frame(br#"{"jsonrpc":"2.0","method":"string-longer-than-sixteen-bytes"}"#),
        Err(McpTransportError::SemanticLimit)
    );
    transport.reset_admission_window();
    let valid = br#"{"jsonrpc":"2.0","method":"x"}"#;
    assert!(transport.decode_frame(valid).is_ok());
    assert!(transport.decode_frame(valid).is_ok());
    assert!(transport.decode_frame(valid).is_ok());
    assert_eq!(
        transport.decode_frame(valid),
        Err(McpTransportError::RateLimit)
    );
}

#[test]
fn cumulative_buffer_bound_applies_across_individually_valid_frames() {
    let mut bounded = limits();
    bounded.max_buffer_bytes = 50;
    let mut transport = BoundedMcpTransport::new(NoIo, bounded);
    let valid = br#"{"jsonrpc":"2.0","method":"x"}"#;
    assert!(transport.decode_frame(valid).is_ok());
    assert_eq!(
        transport.decode_frame(valid),
        Err(McpTransportError::ByteLimit)
    );
}

#[test]
fn malformed_protocol_and_sensitive_error_payload_are_redacted() {
    let mut transport = BoundedMcpTransport::new(NoIo, McpTransportLimits::default());
    assert_eq!(
        transport.decode_frame(br#"{"jsonrpc":"1.0","method":"x"}"#),
        Err(McpTransportError::UnsupportedProtocol)
    );
    assert_eq!(
        transport.decode_frame(br#"{"jsonrpc":"2.0","id":1}"#),
        Err(McpTransportError::MalformedMessage)
    );
    let error = transport
        .decode_frame(
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"secret","data":"token"}}"#,
        )
        .unwrap();
    assert_eq!(error.error_code(), Some(-32000));
    let debug = format!("{error:?}");
    assert!(!debug.contains("secret"));
    assert!(!debug.contains("token"));
}

#[test]
fn production_sdk_profile_is_structurally_disabled() {
    let evidence = McpSdkIntegrationEvidence {
        sdk_version: "2.2.0".to_owned(),
        source_checksum: [1; 32],
        dependency_digest: [2; 32],
        protocol_version: "2025-11-25".to_owned(),
        conformance_digest: [3; 32],
        behavior_evidence_digest: Some([4; 32]),
        platform_evidence_digest: Some([5; 32]),
        supply_chain_evidence_digest: Some([6; 32]),
    };
    assert!(
        McpSdkIntegrationProfileRef::production(
            McpSdkIntegrationProfileId::new("stock").unwrap(),
            1,
            evidence.clone(),
        )
        .is_err()
    );
    assert!(
        McpSdkIntegrationProfileRef::production(
            McpSdkIntegrationProfileId::new("missing-behavior").unwrap(),
            1,
            McpSdkIntegrationEvidence {
                sdk_version: "2.3.0".to_owned(),
                behavior_evidence_digest: None,
                ..evidence
            },
        )
        .is_err()
    );
    let complete = McpSdkIntegrationEvidence {
        sdk_version: "2.3.0".to_owned(),
        source_checksum: [1; 32],
        dependency_digest: [2; 32],
        protocol_version: "2025-11-25".to_owned(),
        conformance_digest: [3; 32],
        behavior_evidence_digest: Some([4; 32]),
        platform_evidence_digest: Some([5; 32]),
        supply_chain_evidence_digest: Some([6; 32]),
    };
    assert!(
        McpSdkIntegrationProfileRef::production(
            McpSdkIntegrationProfileId::new("complete").unwrap(),
            1,
            complete.clone(),
        )
        .is_err()
    );
    assert!(
        McpSdkIntegrationProfileRef::production(
            McpSdkIntegrationProfileId::new("zero-revision").unwrap(),
            0,
            complete,
        )
        .is_err()
    );
}
