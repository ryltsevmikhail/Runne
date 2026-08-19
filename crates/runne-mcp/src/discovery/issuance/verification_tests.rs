use runne_tools::{
    AllowedRootId, ApprovalId, AuthorityId, BoundedArgvV1, CapabilityGrantId, ExecutablePolicyId,
    ExplicitEnvironmentV1, HeldFileIdentityV1, InputBoundsV1, PortableUtf8V1, PrincipalId,
    ProcessFileKindV1, ProcessIdentityBindingV1, ProcessIntentV1, ProcessIoBoundsV1,
    ProcessSymlinkProofV1, SandboxId, StdinPolicyV1, ToolId, ToolRef, ToolVersion, VerifiedCwdV1,
    VerifiedExecutableV1,
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
