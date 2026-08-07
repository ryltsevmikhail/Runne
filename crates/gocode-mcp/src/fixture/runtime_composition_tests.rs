use gocode_tools::{
    AllowedRootId, ApprovalId, ApproverId, AuthorityId, BoundedArgvV1, CapabilityGrantId,
    ExecutablePolicyId, ExplicitEnvironmentV1, HeldFileIdentityV1, HeldProcessTreeHandleV1,
    InputBoundsV1, PortableUtf8V1, PrincipalId, ProcessAttemptIdV1,
    ProcessAuthorizationAuthorityV1, ProcessClaimJournalMemoryV1, ProcessContractHostV1,
    ProcessFileKindV1, ProcessGenerationIdV1, ProcessIdentityBindingV1, ProcessIntentV1,
    ProcessIoBoundsV1, ProcessOwnerIdV1, ProcessPlatformTargetV1, ProcessSessionIdV1,
    ProcessStubDisposition, ProcessSymlinkProofV1, SandboxId, SandboxQualificationProbe,
    StdinPolicyV1, VerifiedCwdV1, VerifiedExecutableV1, production_sandbox_probe,
};
use serde_json::json;

use super::*;
use crate::{McpConnectionId, McpRuntimeInstanceId, McpServerId, McpSessionId};

fn id(value: u8) -> [u8; 16] {
    [value; 16]
}

fn process_tool() -> FixtureTool {
    FixtureTool::new_process_backed(
        "process",
        "1.0.0",
        "process fixture",
        json!({"type":"object","additionalProperties":false}),
        json!({"type":"object","additionalProperties":false}),
    )
    .unwrap()
}

fn runtime(composition: Option<FixtureProcessComposition>) -> FixtureMcpRuntime {
    let identity = FixtureIdentity::new(
        McpServerId::new("fixture-server").unwrap(),
        "1.0.0",
        "fixture-v1",
        "2025-11-25",
    )
    .unwrap();
    let args = (
        FixtureMcpMode::FixtureOnly,
        identity,
        vec![process_tool()],
        FixtureScript::new(vec![FixtureStep::response_at(0, json!({})).unwrap()]).unwrap(),
    );
    match composition {
        Some(composition) => {
            FixtureMcpRuntime::new_with_process_authorities(
                args.0,
                args.1,
                args.2,
                args.3,
                &["process"],
                FixtureLimits::default(),
                FixtureApprovalPolicy::FixtureDeterministicAllow,
                1,
                composition,
            )
            .unwrap()
            .0
        }
        None => FixtureMcpRuntime::new(
            args.0,
            args.1,
            args.2,
            args.3,
            &["process"],
            FixtureLimits::default(),
            FixtureApprovalPolicy::FixtureDeterministicAllow,
            1,
        )
        .unwrap(),
    }
}

fn initialize(runtime: &mut FixtureMcpRuntime, connection: &str, generation: u64) {
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

fn composition() -> (
    FixtureProcessComposition,
    ProcessIntentV1,
    ProcessAuthorizationAuthorityV1,
) {
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
    let binding = ProcessIdentityBindingV1::new(
        PrincipalId::new(id(9)).unwrap(),
        AuthorityId::new(id(10)).unwrap(),
        ProcessOwnerIdV1::new(id(11)).unwrap(),
        ProcessAttemptIdV1::new(id(12)).unwrap(),
        ProcessSessionIdV1::new(id(13)).unwrap(),
        ProcessGenerationIdV1::new(id(14)).unwrap(),
        CapabilityGrantId::new(id(15)).unwrap(),
        SandboxId::new(id(16)).unwrap(),
        HeldProcessTreeHandleV1::new(id(17)).unwrap(),
    );
    let policy = ExecutablePolicyId::new(id(18)).unwrap();
    let root = AllowedRootId::new(id(19)).unwrap();
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
        binding.clone(),
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
    let host = ProcessContractHostV1::new(
        ProcessClaimJournalMemoryV1::new(),
        ProcessPlatformTargetV1::Linux,
        100,
    );
    (
        FixtureProcessComposition::new(authority.clone(), host),
        intent,
        authority,
    )
}

#[test]
fn standard_process_runtime_discovers_without_a_process_gateway() {
    let mut runtime = runtime(None);
    initialize(&mut runtime, "connection-1", 1);

    runtime.discover().unwrap();

    assert!(!runtime.process_gateway_present());
    assert_eq!(runtime.process_composition_metadata(), None);
}

#[test]
#[rustfmt::skip]
fn initial_process_composition_does_not_fence_a_real_call_child() {
    let (composition, intent, authority) = composition();
    let child = authority.bind_call(intent.lifecycle_binding()).unwrap();
    let capability = child.issue_capability(&intent, 20).unwrap();
    let approval = child.approve(&intent, 20, true).unwrap();
    let mut runtime = runtime(Some(composition));
    initialize(&mut runtime, "connection-3", 3);

    runtime.discover().unwrap();
    assert_eq!(
        runtime
            .process_composition_metadata()
            .unwrap()
            .host_compositions(),
        1
    );
    assert_eq!(
        runtime.process_composition_metadata().unwrap().generation(),
        Some(3)
    );
    assert!(child
        .validate(intent, Some(&capability), Some(&approval), 10)
        .is_ok());
    runtime.discover().unwrap();

    assert!(runtime.process_gateway_present());
    assert_eq!(
        runtime
            .process_composition_metadata()
            .unwrap()
            .host_compositions(),
        1
    );
}

#[test]
#[rustfmt::skip]
fn reconnect_advances_the_existing_process_gateway_without_recomposition() {
    let (composition, intent, authority) = composition();
    let child = authority.bind_call(intent.lifecycle_binding()).unwrap();
    let mut runtime = runtime(Some(composition));
    initialize(&mut runtime, "connection-1", 1);
    runtime.discover().unwrap();
    runtime
        .reconnect(McpConnectionId::new("connection-2").unwrap())
        .unwrap();
    assert!(runtime.process_gateway_present());
    initialize(&mut runtime, "connection-2", 2);
    runtime.discover().unwrap();

    let metadata = runtime.process_composition_metadata().unwrap();
    assert_eq!(metadata.host_compositions(), 1);
    assert_eq!(metadata.generation(), Some(2));
    assert!(child.issue_capability(&intent, 20).is_err());
    assert!(runtime.initialize(FixtureInitialize::new(
        McpRuntimeInstanceId::new("runtime-1").unwrap(), McpSessionId::new("session-1").unwrap(),
        McpConnectionId::new("connection-2").unwrap(), 1, "fixture-server", "1.0.0", "fixture-v1", "2025-11-25",
    )).is_err());
    assert_eq!(runtime.process_composition_metadata().unwrap().generation(), Some(2));
}

#[test]
fn qualified_constructor_is_test_only_and_production_composition_uses_not_qualified_probe() {
    assert!(!include_str!("../lib.rs").contains("new_with_probe"));
    assert!(include_str!("process.rs").contains("Arc::new(production_sandbox_probe())"));
    assert_eq!(
        production_sandbox_probe().qualify(),
        Err(ProcessStubDisposition::NotQualified)
    );
}

#[test]
fn r2_process_composition_contains_no_mutable_boundary_or_synthetic_lifecycle() {
    let composition = include_str!("process.rs");
    let authority = include_str!("runtime.rs");

    for legacy in [
        "PROCESS_LIFECYCLE_INVOCATION",
        "fixture-process-lifecycle",
        "binding_advances",
        "Arc<Mutex<ProcessAuthorizationBoundaryV1>>",
    ] {
        assert!(!composition.contains(legacy));
        assert!(!authority.contains(legacy));
    }
}
