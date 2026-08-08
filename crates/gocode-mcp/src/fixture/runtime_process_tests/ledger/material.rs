use super::super::super::process::derive_process_identity_binding;
use super::super::super::runtime::FixtureProcessApprovalAuthority;
use gocode_tools::{
    AllowedRootId, ApprovalId, ApproverId, AuthorityId, BoundedArgvV1, CapabilityGrantId,
    ExecutablePolicyId, ExplicitEnvironmentV1, HeldFileIdentityV1, InputBoundsV1, PortableUtf8V1,
    PrincipalId, ProcessAuthorizationAuthorityV1, ProcessFileKindV1, ProcessIntentV1,
    ProcessIoBoundsV1, ProcessSymlinkProofV1, SandboxId, StdinPolicyV1, VerifiedCwdV1,
    VerifiedExecutableV1,
};

pub(super) fn authority_and_intent(
    binding: &crate::McpDispatchBinding,
    invocation: &str,
) -> (
    FixtureProcessApprovalAuthority,
    ProcessAuthorizationAuthorityV1,
    ProcessIntentV1,
) {
    let id = |value| [value; 16];
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
        &crate::McpInvocationId::new(invocation).unwrap(),
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
            vec![PortableUtf8V1::from_bytes(b"raw-argv-sentinel".to_vec()).unwrap()],
            InputBoundsV1::new(1, 32, 32).unwrap(),
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
    (
        FixtureProcessApprovalAuthority::new(authority.clone()),
        authority,
        intent,
    )
}
