use runne_tools::{
    AllowedRootId, ApprovalId, ApproverId, AuthorityId, BoundedArgvV1, CapabilityGrantId,
    ExecutablePolicyId, ExplicitEnvironmentV1, HeldFileIdentityV1, HeldProcessTreeHandleV1,
    InputBoundsV1, PortableUtf8V1, PrincipalId, ProcessAttemptIdV1,
    ProcessAuthorizationAuthorityV1, ProcessClaimJournalMemoryV1, ProcessContractHostV1,
    ProcessFileKindV1, ProcessGenerationIdV1, ProcessIdentityBindingV1, ProcessIntentV1,
    ProcessIoBoundsV1, ProcessOwnerIdV1, ProcessSessionIdV1, ProcessSymlinkProofV1, SandboxId,
    StdinPolicyV1, VerifiedCwdV1, VerifiedExecutableV1,
};
use serde_json::json;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use super::process::FixtureProcessComposition;
use super::*;
use crate::{
    McpConnectionId, McpGenerationClaimError, McpRuntimeInstanceId, McpServerId, McpSessionId,
};

fn id(value: u8) -> [u8; 16] {
    [value; 16]
}

fn composition() -> (
    FixtureProcessComposition,
    ProcessIntentV1,
    ProcessAuthorizationAuthorityV1,
) {
    composition_with(1, 1)
}

fn composition_with(
    revision: u64,
    epoch: u64,
) -> (
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
        binding,
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
        revision,
        epoch,
        id(22),
    )
    .unwrap();
    let host = ProcessContractHostV1::new(
        ProcessClaimJournalMemoryV1::new(),
        runne_tools::ProcessPlatformTargetV1::Linux,
        100,
    );
    (
        FixtureProcessComposition::new(authority.clone(), host),
        intent,
        authority,
    )
}

fn runtime(composition: FixtureProcessComposition) -> FixtureMcpRuntime {
    FixtureMcpRuntime::new_with_process_authorities(
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
                "process fixture",
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
        composition,
    )
    .unwrap()
    .0
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

#[test]
fn busy_cutover_keeps_the_old_child_and_metadata_then_retries_once() {
    let (composition, intent, authority) = composition();
    let old = authority.bind_call(intent.lifecycle_binding()).unwrap();
    let mut runtime = runtime(composition);
    initialize(&mut runtime, "connection-1", 1);
    let first = runtime.discover().unwrap();
    let generation = runtime.process_generation_authority_for_test().unwrap();
    let (held_sender, held_receiver) = mpsc::channel();
    let (release_sender, release_receiver) = mpsc::channel();
    let held_generation = Arc::clone(&generation);
    let held_binding = first.binding.clone();
    let holder = thread::spawn(move || {
        let permit = held_generation.claim_dispatch(&held_binding);
        held_sender.send(permit.is_ok()).unwrap();
        release_receiver.recv().unwrap();
        drop(permit);
    });
    assert!(held_receiver.recv_timeout(Duration::from_secs(1)).unwrap());
    runtime
        .reconnect(McpConnectionId::new("connection-2").unwrap())
        .unwrap();
    initialize(&mut runtime, "connection-2", 2);

    assert!(matches!(
        runtime.discover(),
        Err(FixtureMcpFailure::InvalidStateTransition)
    ));
    assert!(old.issue_capability(&intent, 20).is_ok());
    assert_eq!(
        runtime.process_composition_metadata().unwrap().generation(),
        Some(1)
    );
    release_sender.send(()).unwrap();
    holder.join().unwrap();

    let second = runtime.discover().unwrap();
    assert!(matches!(
        generation.claim_dispatch(&first.binding),
        Err(McpGenerationClaimError::Stale)
    ));
    assert!(generation.claim_dispatch(&second.binding).is_ok());
    assert!(old.issue_capability(&intent, 20).is_err());
    let fresh = authority.bind_call(intent.lifecycle_binding()).unwrap();
    let fresh_capability = fresh.issue_capability(&intent, 20).unwrap();
    let fresh_approval = fresh.approve(&intent, 20, true).unwrap();
    assert_eq!(
        runtime
            .process_composition_metadata()
            .unwrap()
            .host_compositions(),
        1
    );
    assert_eq!(
        runtime.process_composition_metadata().unwrap().generation(),
        Some(2)
    );
    runtime.discover().unwrap();
    assert!(
        fresh
            .validate(intent, Some(&fresh_capability), Some(&fresh_approval), 10)
            .is_ok()
    );
    assert_eq!(
        runtime
            .process_composition_metadata()
            .unwrap()
            .host_compositions(),
        1
    );
    assert_eq!(
        runtime.process_composition_metadata().unwrap().generation(),
        Some(2)
    );
}

mod r3_failures;
mod source_order;
