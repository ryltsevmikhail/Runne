pub(super) use runne_tools::{
    AllowedRootId, ApprovalId, ApproverId, AuthorityId, BoundedArgvV1, CapabilityGrantId,
    ExecutablePolicyId, ExplicitEnvironmentV1, HeldFileIdentityV1, InputBoundsV1, PortableUtf8V1,
    PrincipalId, ProcessAuthorizationAuthorityV1, ProcessFileKindV1, ProcessIntentV1,
    ProcessIoBoundsV1, ProcessSymlinkProofV1, SandboxId, StdinPolicyV1, VerifiedCwdV1,
    VerifiedExecutableV1,
};
pub(super) use serde_json::json;

use super::super::process::derive_process_identity_binding;
use super::super::runtime::FixtureProcessApprovalAuthority;
pub(super) use super::super::*;
pub(super) use crate::{
    McpConnectionId, McpDispatchBinding, McpInvocationId, McpRuntimeInstanceId, McpServerId,
    McpSessionId,
};

pub(super) fn id(value: u8) -> [u8; 16] {
    [value; 16]
}

pub(super) fn runtime() -> FixtureMcpRuntime {
    FixtureMcpRuntime::new(
        FixtureMcpMode::FixtureOnly,
        FixtureIdentity::new(
            McpServerId::new("fixture-server").unwrap(),
            "1.0.0",
            "fixture-v1",
            "2025-11-25",
        )
        .unwrap(),
        vec![
            FixtureTool::new_process_backed(
                "process",
                "1.0.0",
                "fixture",
                json!({"type":"object","additionalProperties":false}),
                json!({"type":"object","additionalProperties":false}),
            )
            .unwrap(),
        ],
        FixtureScript::new(vec![FixtureStep::response_at(0, json!({})).unwrap()]).unwrap(),
        &["process"],
        FixtureLimits::default(),
        FixtureApprovalPolicy::FixtureDeterministicAllow,
        1,
    )
    .unwrap()
}

pub(super) fn initialize(runtime: &mut FixtureMcpRuntime) {
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

pub(super) fn authority_and_intent(
    binding: &McpDispatchBinding,
    invocation: &str,
) -> (FixtureProcessApprovalAuthority, ProcessIntentV1) {
    let file = |value| {
        HeldFileIdentityV1::new(id(value), [value; 32], [value + 1; 32], [value + 2; 32], 1)
            .unwrap()
    };
    let executable = VerifiedExecutableV1::new(
        file(1),
        ProcessFileKindV1::RegularFile,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .unwrap();
    let cwd = VerifiedCwdV1::new(
        file(5),
        ProcessFileKindV1::Directory,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .unwrap();
    let policy = ExecutablePolicyId::new(id(18)).unwrap();
    let root = AllowedRootId::new(id(19)).unwrap();
    let lifecycle = derive_process_identity_binding(
        binding,
        &McpInvocationId::new(invocation).unwrap(),
        PrincipalId::new(id(9)).unwrap(),
        AuthorityId::new(id(10)).unwrap(),
        CapabilityGrantId::new(id(15)).unwrap(),
        SandboxId::new(id(16)).unwrap(),
    );
    let intent = ProcessIntentV1::new(
        ApprovalId::new(id(20)).unwrap(),
        executable.clone(),
        policy.clone(),
        cwd.clone(),
        root.clone(),
        BoundedArgvV1::new(
            vec![PortableUtf8V1::from_bytes(b"tool".to_vec()).unwrap()],
            InputBoundsV1::new(1, 4, 4).unwrap(),
        )
        .unwrap(),
        ExplicitEnvironmentV1::empty(),
        StdinPolicyV1::closed(),
        ProcessIoBoundsV1::new(4, 4, 8, 1, true).unwrap(),
        lifecycle,
    )
    .unwrap();
    let authority = ProcessAuthorizationAuthorityV1::new(
        executable,
        policy,
        cwd,
        root,
        PrincipalId::new(id(9)).unwrap(),
        AuthorityId::new(id(10)).unwrap(),
        CapabilityGrantId::new(id(15)).unwrap(),
        SandboxId::new(id(16)).unwrap(),
        ApproverId::new(id(21)).unwrap(),
        1,
        1,
        id(22),
    )
    .unwrap();
    (FixtureProcessApprovalAuthority::new(authority), intent)
}
