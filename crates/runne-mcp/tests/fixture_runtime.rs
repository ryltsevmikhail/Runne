use runne_mcp::{
    FixtureApprovalPolicy, FixtureCallResult, FixtureIdentity, FixtureInitialize, FixtureLimits,
    FixtureMcpFailure, FixtureMcpMode, FixtureMcpRuntime, FixtureScript, FixtureStep, FixtureTool,
    McpConnectionId, McpRuntimeInstanceId, McpServerId, McpSessionId,
};
use serde_json::json;

fn runtime() -> FixtureMcpRuntime {
    runtime_with(
        response_script(),
        FixtureApprovalPolicy::FixtureDeterministicAllow,
        2,
    )
}

fn response_script() -> FixtureScript {
    FixtureScript::new(vec![FixtureStep::response_at(0, json!({})).unwrap()]).unwrap()
}

fn runtime_with(
    script: FixtureScript,
    policy: FixtureApprovalPolicy,
    accounting_limit: u64,
) -> FixtureMcpRuntime {
    runtime_with_authority(script, policy, accounting_limit).0
}

fn runtime_with_authority(
    script: FixtureScript,
    policy: FixtureApprovalPolicy,
    accounting_limit: u64,
) -> (FixtureMcpRuntime, runne_mcp::FixtureApprovalAuthority) {
    FixtureMcpRuntime::new_with_approval_authority(
        FixtureMcpMode::FixtureOnly,
        FixtureIdentity::new(
            McpServerId::new("fixture-server").unwrap(), "1.0.0", "fixture-v1", "2025-11-25",
        ).unwrap(),
        vec![FixtureTool::new(
            "read", "1.0.0", "safe read",
            json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"],"additionalProperties":false}),
            json!({"type":"object","additionalProperties":false}),
        ).unwrap()],
        script, &["read"], FixtureLimits::default(), policy, accounting_limit,
    ).unwrap()
}

fn runtime_with_definition(
    tools: Vec<FixtureTool>,
    script: FixtureScript,
    allowlist: &[&str],
    policy: FixtureApprovalPolicy,
    accounting_limit: u64,
) -> FixtureMcpRuntime {
    FixtureMcpRuntime::new(
        FixtureMcpMode::FixtureOnly,
        FixtureIdentity::new(
            McpServerId::new("fixture-server").unwrap(),
            "1.0.0",
            "fixture-v1",
            "2025-11-25",
        )
        .unwrap(),
        tools,
        script,
        allowlist,
        FixtureLimits::default(),
        policy,
        accounting_limit,
    )
    .unwrap()
}

fn read_tool(input_schema: serde_json::Value) -> FixtureTool {
    FixtureTool::new(
        "read",
        "1.0.0",
        "safe read",
        input_schema,
        json!({"type":"object","additionalProperties":false}),
    )
    .unwrap()
}

fn initialize(runtime: &mut FixtureMcpRuntime) {
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
}

include!("fixture_runtime/lifecycle.rs");
include!("fixture_runtime/discovery.rs");
include!("fixture_runtime/validation.rs");
include!("fixture_runtime/security.rs");
include!("fixture_runtime/process.rs");
include!("fixture_runtime/issuance_lock.rs");
