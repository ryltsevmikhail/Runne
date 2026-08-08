use super::super::super::super::process::derive_process_identity_binding;
use crate::McpInvocationId;
use gocode_tools::{
    AllowedRootId, ApprovalId, ApproverId, AuthorityId, BoundedArgvV1, CapabilityGrantId,
    ExecutablePolicyId, ExplicitEnvironmentV1, HeldFileIdentityV1, InputBoundsV1, PortableUtf8V1,
    PrincipalId, ProcessAuthorizationAuthorityV1, ProcessFileKindV1, ProcessIntentV1,
    ProcessIoBoundsV1, ProcessSymlinkProofV1, SandboxId, StdinPolicyV1, VerifiedCwdV1,
    VerifiedExecutableV1,
};

pub(super) fn authority() -> ProcessAuthorizationAuthorityV1 {
    let (executable, policy, cwd, root) = material();
    ProcessAuthorizationAuthorityV1::new(
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
    .unwrap()
}

pub(super) fn intent(binding: &crate::McpDispatchBinding, invocation: &str) -> ProcessIntentV1 {
    let (executable, policy, cwd, root) = material();
    ProcessIntentV1::new(
        ApprovalId::new(id(20)).unwrap(),
        executable,
        policy,
        cwd,
        root,
        BoundedArgvV1::new(
            vec![PortableUtf8V1::from_bytes(b"tool".to_vec()).unwrap()],
            InputBoundsV1::new(1, 4, 4).unwrap(),
        )
        .unwrap(),
        ExplicitEnvironmentV1::empty(),
        StdinPolicyV1::closed(),
        ProcessIoBoundsV1::new(4, 4, 8, 1, true).unwrap(),
        derive_process_identity_binding(
            binding,
            &McpInvocationId::new(invocation).unwrap(),
            PrincipalId::new(id(9)).unwrap(),
            AuthorityId::new(id(10)).unwrap(),
            CapabilityGrantId::new(id(15)).unwrap(),
            SandboxId::new(id(16)).unwrap(),
        ),
    )
    .unwrap()
}

fn material() -> (
    VerifiedExecutableV1,
    ExecutablePolicyId,
    VerifiedCwdV1,
    AllowedRootId,
) {
    let file = |value| {
        HeldFileIdentityV1::new(id(value), [value; 32], [value + 1; 32], [value + 2; 32], 1)
            .unwrap()
    };
    (
        VerifiedExecutableV1::new(
            file(1),
            ProcessFileKindV1::RegularFile,
            ProcessSymlinkProofV1::VerifiedNotSymlink,
        )
        .unwrap(),
        ExecutablePolicyId::new(id(18)).unwrap(),
        VerifiedCwdV1::new(
            file(5),
            ProcessFileKindV1::Directory,
            ProcessSymlinkProofV1::VerifiedNotSymlink,
        )
        .unwrap(),
        AllowedRootId::new(id(19)).unwrap(),
    )
}

const fn id(value: u8) -> [u8; 16] {
    [value; 16]
}
