use runne_tools::{
    AllowedRootId, ApprovalId, AuthorityId, BoundedArgvV1, CapabilityGrantId, ExecutablePolicyId,
    ExplicitEnvironmentV1, HeldFileIdentityV1, HeldProcessTreeHandleV1, InputBoundsV1,
    PortableUtf8V1, PrincipalId, ProcessAttemptIdV1, ProcessFileKindV1, ProcessGenerationIdV1,
    ProcessIdentityBindingV1, ProcessIntentV1, ProcessIoBoundsV1, ProcessLifecycleBindingV1,
    ProcessOwnerIdV1, ProcessSessionIdV1, ProcessSymlinkProofV1, SandboxId, StdinPolicyV1, ToolId,
    ToolRef, ToolVersion, VerifiedCwdV1, VerifiedExecutableV1,
};
use serde_json::json;

use super::super::{
    McpDispatchBinding, McpToolDispatchCapability, McpToolExecutionClass, call_digest,
};
use super::{ProcessCallBindingError, derive_process_lifecycle_binding};
use crate::{McpConnectionId, McpInvocationId, McpRuntimeInstanceId, McpServerId, McpSessionId};

fn id(value: u8) -> [u8; 16] {
    [value; 16]
}

fn process_intent(binding: ProcessIdentityBindingV1) -> ProcessIntentV1 {
    let file = |value| {
        HeldFileIdentityV1::new(id(value), [value; 32], [value + 1; 32], [value + 2; 32], 1)
            .unwrap()
    };
    ProcessIntentV1::new(
        ApprovalId::new(id(1)).unwrap(),
        VerifiedExecutableV1::new(
            file(2),
            ProcessFileKindV1::RegularFile,
            ProcessSymlinkProofV1::VerifiedNotSymlink,
        )
        .unwrap(),
        ExecutablePolicyId::new(id(3)).unwrap(),
        VerifiedCwdV1::new(
            file(4),
            ProcessFileKindV1::Directory,
            ProcessSymlinkProofV1::VerifiedNotSymlink,
        )
        .unwrap(),
        AllowedRootId::new(id(5)).unwrap(),
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
    .unwrap()
}

fn capability() -> (McpToolDispatchCapability, ProcessIntentV1) {
    let binding = McpDispatchBinding::new(
        McpServerId::new("server").unwrap(),
        McpRuntimeInstanceId::new("runtime").unwrap(),
        McpConnectionId::new("connection").unwrap(),
        McpSessionId::new("session").unwrap(),
        1,
        [1; 32],
    )
    .unwrap();
    let invocation_id = McpInvocationId::new("invocation-a").unwrap();
    let tool_ref = ToolRef::new(
        ToolId::new("fixture::process").unwrap(),
        ToolVersion::new("1.0.0").unwrap(),
    );
    let input = json!({});
    let lifecycle = derive_process_lifecycle_binding(&binding, &invocation_id);
    let intent = process_intent(ProcessIdentityBindingV1::new(
        PrincipalId::new(id(6)).unwrap(),
        AuthorityId::new(id(7)).unwrap(),
        lifecycle.owner().clone(),
        lifecycle.attempt().clone(),
        lifecycle.session().clone(),
        lifecycle.generation().clone(),
        CapabilityGrantId::new(id(8)).unwrap(),
        SandboxId::new(id(9)).unwrap(),
        lifecycle.tree_handle().clone(),
    ));
    let capability = McpToolDispatchCapability {
        request_digest: call_digest(&binding, &tool_ref, &invocation_id, &input),
        binding,
        tool_ref,
        invocation_id,
        input,
        server_tool_name: "process".into(),
        execution_class: McpToolExecutionClass::ProcessBacked,
        process_intent_digest: Some(intent.digest()),
    };
    (capability, intent)
}

#[test]
fn c2b_verifier_rejects_missing_process_digest_without_consuming_the_capability() {
    let (mut capability, intent) = capability();
    capability.process_intent_digest = None;

    assert!(matches!(
        capability.verify_c2b(&intent),
        Err(ProcessCallBindingError::ProcessIntentRequired)
    ));
    assert!(capability.verify_c2b(&intent).is_err());
}

#[test]
fn c2b_verifier_rejects_forged_cross_invocation_request_before_lifecycle_admission() {
    let (mut capability, intent) = capability();
    capability.invocation_id = McpInvocationId::new("invocation-b").unwrap();

    assert!(matches!(
        capability.verify_c2b(&intent),
        Err(ProcessCallBindingError::InvalidBinding)
    ));
}

#[test]
fn source_pinned_lifecycle_binding_rejects_same_version_runne_identity() {
    let (mut capability, _) = capability();
    let lifecycle =
        derive_process_lifecycle_binding(&capability.binding, &capability.invocation_id);

    assert_eq!(
        lifecycle.owner().as_bytes(),
        &[
            0x75, 0x66, 0x7a, 0x58, 0xe3, 0x7e, 0x09, 0x31, 0x45, 0xc0, 0xc2, 0xb0, 0x80, 0x27,
            0x85, 0xe1
        ]
    );
    assert_eq!(
        lifecycle.attempt().as_bytes(),
        &[
            0xe8, 0x67, 0x75, 0x33, 0xbb, 0x65, 0xd2, 0x4b, 0x0a, 0x8e, 0x2f, 0x1b, 0x2d, 0xf2,
            0xa4, 0xa0
        ]
    );
    assert_eq!(
        lifecycle.session().as_bytes(),
        &[
            0x72, 0x95, 0x11, 0xcb, 0x0f, 0x8a, 0x85, 0x6d, 0xf7, 0xe2, 0x29, 0x60, 0x8c, 0x64,
            0x0e, 0x7f
        ]
    );
    assert_eq!(
        lifecycle.generation().as_bytes(),
        &[
            0xb3, 0x98, 0xab, 0x24, 0xad, 0xda, 0x5f, 0x2d, 0x66, 0x93, 0x25, 0x7e, 0xca, 0xe2,
            0x5c, 0x93
        ]
    );
    assert_eq!(
        lifecycle.tree_handle().as_bytes(),
        &[
            0xfa, 0xc3, 0x8c, 0xc1, 0x6b, 0xdd, 0x72, 0xac, 0xe9, 0x9e, 0xe4, 0xad, 0x6d, 0xec,
            0xbf, 0x3f
        ]
    );

    let stale_mechanical_binding_digest = [
        0xe6, 0x21, 0x53, 0x16, 0x47, 0x05, 0xea, 0xd6, 0x59, 0x2e, 0x05, 0xb4, 0xc8, 0x6e, 0x51,
        0x27, 0x82, 0xbc, 0xdf, 0xca, 0x8d, 0x69, 0x86, 0x10, 0xc6, 0xa1, 0xcf, 0x07, 0xbf, 0x45,
        0x74, 0x13,
    ];
    assert_ne!(
        capability.binding.binding_digest(),
        stale_mechanical_binding_digest
    );
    let stale_mechanical_lifecycle = ProcessLifecycleBindingV1::new(
        ProcessOwnerIdV1::new([
            0xf3, 0x80, 0x3a, 0x2b, 0xba, 0xec, 0x9a, 0x7c, 0x2f, 0xa7, 0x4d, 0x8c, 0x57, 0x52,
            0x69, 0x25,
        ])
        .unwrap(),
        ProcessAttemptIdV1::new([
            0xaa, 0x13, 0x18, 0x97, 0x1f, 0x94, 0x4d, 0x4c, 0x21, 0xe7, 0x29, 0x4a, 0xad, 0x6a,
            0xc5, 0x5f,
        ])
        .unwrap(),
        ProcessSessionIdV1::new([
            0x71, 0xf1, 0xbe, 0xa3, 0xff, 0xf0, 0xc2, 0x95, 0xc0, 0xc0, 0x9c, 0x0f, 0x7e, 0xf9,
            0x44, 0x04,
        ])
        .unwrap(),
        ProcessGenerationIdV1::new([
            0x4d, 0xe2, 0xcc, 0xcf, 0xfe, 0x56, 0x2b, 0xbb, 0xa5, 0x79, 0xd6, 0x74, 0x95, 0xc5,
            0x44, 0xd5,
        ])
        .unwrap(),
        HeldProcessTreeHandleV1::new([
            0xd8, 0x28, 0xde, 0x44, 0x8b, 0x30, 0x25, 0x0b, 0xbb, 0xb1, 0xe8, 0xd6, 0x84, 0x44,
            0xdc, 0x20,
        ])
        .unwrap(),
    );
    assert_ne!(lifecycle, stale_mechanical_lifecycle);
    let stale_mechanical_intent = process_intent(ProcessIdentityBindingV1::new(
        PrincipalId::new(id(6)).unwrap(),
        AuthorityId::new(id(7)).unwrap(),
        stale_mechanical_lifecycle.owner().clone(),
        stale_mechanical_lifecycle.attempt().clone(),
        stale_mechanical_lifecycle.session().clone(),
        stale_mechanical_lifecycle.generation().clone(),
        CapabilityGrantId::new(id(8)).unwrap(),
        SandboxId::new(id(9)).unwrap(),
        stale_mechanical_lifecycle.tree_handle().clone(),
    ));
    capability.process_intent_digest = Some(stale_mechanical_intent.digest());
    assert_eq!(
        capability.verify_c2b(&stale_mechanical_intent),
        Err(ProcessCallBindingError::InvalidBinding)
    );
}
