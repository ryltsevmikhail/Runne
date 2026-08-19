use runne_platform_ports::process::{
    HeldFileIdentityV1, HeldProcessTreeHandleV1, ProcessAttemptIdV1, ProcessFileKindV1,
    ProcessGenerationIdV1, ProcessOwnerIdV1, ProcessSessionIdV1, ProcessSymlinkProofV1,
    VerifiedCwdV1, VerifiedExecutableV1,
};
use runne_security::process_contract::{
    AllowedRootId, ApprovalId, AuthorityId, BoundedArgvV1, CapabilityGrantId, ExecutablePolicyId,
    ExplicitEnvironmentV1, InputBoundsV1, PortableUtf8V1, PrincipalId, ProcessIdentityBindingV1,
    ProcessIntentV1, ProcessIoBoundsV1, SandboxId, StdinPolicyV1,
};

pub const MARKER: &str = "shell-like; $(not-a-command) --marker";

pub fn text(value: &str) -> PortableUtf8V1 {
    PortableUtf8V1::from_bytes(value.as_bytes().to_vec()).expect("test text is portable")
}

pub fn bounds() -> InputBoundsV1 {
    InputBoundsV1::new(4, 128, 256).expect("test bounds are valid")
}

pub fn intent(argv: Vec<PortableUtf8V1>) -> ProcessIntentV1 {
    ProcessIntentV1::new(
        ApprovalId::new(id(1)).expect("non-zero approval"),
        executable(2),
        ExecutablePolicyId::new(id(3)).expect("non-zero policy"),
        cwd(4),
        AllowedRootId::new(id(5)).expect("non-zero root"),
        BoundedArgvV1::new(argv, bounds()).expect("bounded argv"),
        ExplicitEnvironmentV1::empty(),
        StdinPolicyV1::closed(),
        ProcessIoBoundsV1::new(16, 16, 32, 1, true).expect("valid I/O bounds"),
        ProcessIdentityBindingV1::new(
            PrincipalId::new(id(6)).expect("non-zero principal"),
            AuthorityId::new(id(7)).expect("non-zero authority"),
            ProcessOwnerIdV1::new(id(8)).expect("non-zero owner"),
            ProcessAttemptIdV1::new(id(9)).expect("non-zero attempt"),
            ProcessSessionIdV1::new(id(10)).expect("non-zero session"),
            ProcessGenerationIdV1::new(id(11)).expect("non-zero generation"),
            CapabilityGrantId::new(id(12)).expect("non-zero grant"),
            SandboxId::new(id(13)).expect("non-zero sandbox"),
            HeldProcessTreeHandleV1::new(id(14)).expect("non-zero tree"),
        ),
    )
    .expect("synthetic intent is valid")
}

fn executable(value: u8) -> VerifiedExecutableV1 {
    VerifiedExecutableV1::new(
        file(value),
        ProcessFileKindV1::RegularFile,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .expect("synthetic executable is valid")
}

fn cwd(value: u8) -> VerifiedCwdV1 {
    VerifiedCwdV1::new(
        file(value),
        ProcessFileKindV1::Directory,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .expect("synthetic cwd is valid")
}

fn file(value: u8) -> HeldFileIdentityV1 {
    HeldFileIdentityV1::new(id(value), [value; 32], [value + 1; 32], [value + 2; 32], 1)
        .expect("synthetic file identity is valid")
}

const fn id(value: u8) -> [u8; 16] {
    [value; 16]
}
