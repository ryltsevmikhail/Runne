use gocode_platform_ports::process::{
    HeldFileIdentityV1, HeldProcessTreeHandleV1, ProcessAttemptIdV1, ProcessFileKindV1,
    ProcessGenerationIdV1, ProcessOwnerIdV1, ProcessSessionIdV1, ProcessSymlinkProofV1,
    VerifiedCwdV1, VerifiedExecutableV1,
};

use super::super::{
    AllowedRootId, ApprovalId, ApproverId, AuthorityId, BoundedArgvV1, CapabilityGrantId,
    ExecutablePolicyId, ExplicitEnvironmentV1, InputBoundsV1, PortableUtf8V1, PrincipalId,
    ProcessCapabilityId, ProcessIdentityBindingV1, ProcessIntentV1, ProcessIoBoundsV1, SandboxId,
    StdinPolicyV1,
};

pub(super) fn id<const N: usize>(value: u8) -> [u8; N] {
    [value; N]
}

pub(super) fn binding(value: u8) -> ProcessIdentityBindingV1 {
    binding_parts(value, value + 1, value + 2, value + 3, value + 4, value + 5)
}

pub(super) fn binding_parts(
    principal: u8,
    authority: u8,
    owner: u8,
    attempt: u8,
    session: u8,
    generation: u8,
) -> ProcessIdentityBindingV1 {
    ProcessIdentityBindingV1::new(
        PrincipalId::new(id(principal)).unwrap(),
        AuthorityId::new(id(authority)).unwrap(),
        ProcessOwnerIdV1::new(id(owner)).unwrap(),
        ProcessAttemptIdV1::new(id(attempt)).unwrap(),
        ProcessSessionIdV1::new(id(session)).unwrap(),
        ProcessGenerationIdV1::new(id(generation)).unwrap(),
        CapabilityGrantId::new(id(7)).unwrap(),
        SandboxId::new(id(8)).unwrap(),
        HeldProcessTreeHandleV1::new(id(9)).unwrap(),
    )
}

pub(super) fn executable(
    token: u8,
    canonical: u8,
    content: u8,
    filesystem: u8,
    version: u64,
) -> VerifiedExecutableV1 {
    VerifiedExecutableV1::new(
        file(token, canonical, content, filesystem, version),
        ProcessFileKindV1::RegularFile,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .unwrap()
}

pub(super) fn cwd(token: u8, canonical: u8, filesystem: u8, version: u64) -> VerifiedCwdV1 {
    cwd_with_content(token, canonical, 12, filesystem, version)
}

pub(super) fn cwd_with_content(
    token: u8,
    canonical: u8,
    content: u8,
    filesystem: u8,
    version: u64,
) -> VerifiedCwdV1 {
    VerifiedCwdV1::new(
        file(token, canonical, content, filesystem, version),
        ProcessFileKindV1::Directory,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .unwrap()
}

fn file(token: u8, canonical: u8, content: u8, filesystem: u8, version: u64) -> HeldFileIdentityV1 {
    HeldFileIdentityV1::new(
        id(token),
        id(canonical),
        id(content),
        id(filesystem),
        version,
    )
    .unwrap()
}

pub(super) fn intent(
    binding: ProcessIdentityBindingV1,
    approval: u8,
    executable: VerifiedExecutableV1,
    policy: u8,
    cwd: VerifiedCwdV1,
    root: u8,
) -> ProcessIntentV1 {
    ProcessIntentV1::new(
        ApprovalId::new(id(approval)).unwrap(),
        executable,
        ExecutablePolicyId::new(id(policy)).unwrap(),
        cwd,
        AllowedRootId::new(id(root)).unwrap(),
        BoundedArgvV1::new(
            vec![PortableUtf8V1::from_bytes(b"tool".to_vec()).unwrap()],
            InputBoundsV1::new(2, 16, 16).unwrap(),
        )
        .unwrap(),
        ExplicitEnvironmentV1::empty(),
        StdinPolicyV1::closed(),
        ProcessIoBoundsV1::new(4, 4, 8, 1, true).unwrap(),
        binding,
    )
    .unwrap()
}

pub(super) fn baseline() -> ProcessIntentV1 {
    intent(
        binding(1),
        10,
        executable(1, 2, 3, 4, 1),
        11,
        cwd(5, 6, 7, 1),
        12,
    )
}
pub(super) fn capability(value: u8) -> ProcessCapabilityId {
    ProcessCapabilityId::new(id(value)).unwrap()
}
pub(super) fn approver(value: u8) -> ApproverId {
    ApproverId::new(id(value)).unwrap()
}
