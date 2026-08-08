use super::*;

pub(in crate::fixture) fn protocol_fixture()
-> (FixtureMcpRuntime, FixtureApproval, FixtureCallCapability) {
    let (mut runtime, authority) = FixtureMcpRuntime::new_with_approval_authority(
        FixtureMcpMode::FixtureOnly,
        identity(),
        vec![
            FixtureTool::new(
                "protocol",
                "1.0.0",
                "fixture",
                json!({"type":"object","additionalProperties":false}),
                json!({"type":"object","additionalProperties":false}),
            )
            .unwrap(),
        ],
        script(),
        &["protocol"],
        FixtureLimits::default(),
        FixtureApprovalPolicy::ExplicitPerCall,
        1,
    )
    .unwrap();
    initialize(&mut runtime, "connection-1", 1);
    let publication = runtime.discover().unwrap();
    let capability = publication
        .issue_dispatch(
            "protocol",
            "protocol-regression",
            json!({}),
            "principal",
            "authority",
            20,
        )
        .unwrap();
    let approval = authority.approve(&capability).unwrap();
    (runtime, approval, capability)
}

pub(super) fn initialize(runtime: &mut FixtureMcpRuntime, connection: &str, generation: u64) {
    runtime
        .initialize(FixtureInitialize::new(
            McpRuntimeInstanceId::new("runtime-1").unwrap(),
            McpSessionId::new("session-1").unwrap(),
            McpConnectionId::new(connection).unwrap(),
            generation,
            "fixture-server",
            "1.0.0",
            "fixture-v1",
            "2025-11-25",
        ))
        .unwrap();
}

pub(super) fn identity() -> FixtureIdentity {
    FixtureIdentity::new(
        McpServerId::new("fixture-server").unwrap(),
        "1.0.0",
        "fixture-v1",
        "2025-11-25",
    )
    .unwrap()
}

pub(super) fn process_tool() -> FixtureTool {
    FixtureTool::new_process_backed(
        "process",
        "1.0.0",
        "fixture",
        json!({"type":"object","additionalProperties":false}),
        json!({"type":"object","additionalProperties":false}),
    )
    .unwrap()
}

pub(super) fn script() -> FixtureScript {
    FixtureScript::new(vec![FixtureStep::response_at(0, json!({})).unwrap()]).unwrap()
}
