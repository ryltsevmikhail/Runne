use crate::{McpRuntimeInstanceId, McpServerId, McpSessionId};

use super::model::FixtureStep;

fn source_pin_hex(value: [u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn source_pinned_fixture_runtime_and_response_digests_reject_runne_aliases() {
    let identity = FixtureIdentity::new(
        McpServerId::new("fixture-server").unwrap(),
        "1.0.0",
        "fixture-v1",
        "2025-11-25",
    )
    .unwrap();
    let script = FixtureScript::new(vec![
        FixtureStep::response_at(0, serde_json::json!({})).unwrap(),
    ])
    .unwrap();
    let tool = FixtureTool::new(
        "read",
        "1.0.0",
        "safe read",
        serde_json::json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"],"additionalProperties":false}),
        serde_json::json!({"type":"object","additionalProperties":false}),
    )
    .unwrap();
    assert_eq!(
        source_pin_hex(identity.definition_digest()),
        "7b580ba3f12361fd93ef483b523aa39a6aa14edb2d10e189b21cf17122d19ce1"
    );
    assert_ne!(
        source_pin_hex(identity.definition_digest()),
        "06f7ab5d9dc3b921c716bf68241c7cef8d42fe67027966dc9d9e7a1af9f47116"
    );
    assert_eq!(
        source_pin_hex(script.digest()),
        "7b047e69a98ff87db385136b0e7fba8ab0331ee3a76928fb9c06650ee77e6290"
    );
    assert_ne!(
        source_pin_hex(script.digest()),
        "40b43fe9e26edb0f90bdcf7ae587c7560b21c3b02da9a6f777756b5acccf2ba8"
    );
    assert_eq!(
        source_pin_hex(tool.definition_digest()),
        "3ab025011940375e9a1456fd35e222308da90d5107ef338a30de1e89c11d22a4"
    );
    assert_ne!(
        source_pin_hex(tool.definition_digest()),
        "0b875f69a27794b73353f99aab8905c832adec229dfe02997e610d354a30ba91"
    );

    let mut runtime = FixtureMcpRuntime::new(
        FixtureMcpMode::FixtureOnly,
        identity,
        vec![tool],
        script,
        &["read"],
        FixtureLimits::default(),
        FixtureApprovalPolicy::FixtureDeterministicAllow,
        2,
    )
    .unwrap();
    assert_eq!(
        source_pin_hex(runtime.definition_digest()),
        "67f6ce65aaf9f8acb15e77f5d1927e7e760e5900fa3c48766577acd8caec79ad"
    );
    assert_ne!(
        source_pin_hex(runtime.definition_digest()),
        "bff8643bba6587e57a6bf29a407e563c933fd7fb330059addadc4c61bf4e00e0"
    );

    runtime
        .initialize(FixtureInitialize::new(
            McpRuntimeInstanceId::new("runtime-1").unwrap(),
            McpSessionId::new("session-1").unwrap(),
            McpConnectionId::new("connection-1").unwrap(),
            1,
            "fixture-server",
            "1.0.0",
            "fixture-v1",
            "2025-11-25",
        ))
        .unwrap();
    let mut capability = runtime
        .discover()
        .unwrap()
        .issue_dispatch(
            "read",
            "fixture-response",
            serde_json::json!({"name":"ok"}),
            "p",
            "a",
            1,
        )
        .unwrap();
    assert_eq!(
        runtime.dispatch(&mut capability, None),
        Ok(FixtureCallResult::Completed)
    );
    let terminal = runtime
        .state
        .lock()
        .unwrap()
        .protocol_reservations
        .get("fixture-response")
        .unwrap()
        .terminal_digest
        .unwrap();
    assert_eq!(
        source_pin_hex(terminal),
        "d40409539bf293a4ca16f9942c598a031c78261af7734390b8639436a62af6f7"
    );
    assert_ne!(
        source_pin_hex(terminal),
        "f009a3acc38d5a0a229d1dce10f052047fd26797e08258bdbb2e4f33147a3431"
    );
}
