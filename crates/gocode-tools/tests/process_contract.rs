#[path = "process_contract/source_lexer.rs"]
mod source_lexer;
#[path = "process_contract/source_lexer_concat.rs"]
mod source_lexer_concat;
#[path = "process_contract/source_manifest.rs"]
mod source_manifest;
#[path = "process_contract/source_scan_alias.rs"]
mod source_scan_alias;

use gocode_tools::{
    AllowedRootId, ApprovalId, ApproverId, AuthorityId, BoundedArgvV1, CapabilityGrantId,
    EffectAdmission, ExecutablePolicyId, ExplicitEnvironmentV1, HeldFileIdentityV1,
    HeldProcessTreeHandleV1, InputBoundsV1, PortableUtf8V1, PrincipalId, ProcessAttemptIdV1,
    ProcessAuthorizationAuthorityV1, ProcessClaimJournalMemoryV1, ProcessContractHostV1,
    ProcessFileKindV1, ProcessGenerationIdV1, ProcessHostOutcomeV1, ProcessIdentityBindingV1,
    ProcessIntentV1, ProcessIoBoundsV1, ProcessLifecycleStateV1, ProcessOwnerIdV1,
    ProcessPlatformTargetV1, ProcessSessionIdV1, ProcessSymlinkProofV1, SandboxId, StdinPolicyV1,
    ValidatedProcessIntentV1, VerifiedCwdV1, VerifiedExecutableV1,
};

include!("process_contract/source_scan.rs");
include!("process_contract/integration_surface_scan.rs");
include!("process_contract/output.rs");
include!("process_contract/control.rs");
include!("process_contract/public_api.rs");
include!("process_contract/scenario_matrix.rs");

const fn identity(value: u8) -> [u8; 16] {
    [value; 16]
}

fn test_host() -> ProcessContractHostV1 {
    ProcessContractHostV1::new(
        ProcessClaimJournalMemoryV1::new(),
        ProcessPlatformTargetV1::Linux,
        100,
    )
}

fn test_intent() -> ValidatedProcessIntentV1 {
    let file = |value| {
        HeldFileIdentityV1::new(
            identity(value),
            [value; 32],
            [value + 1; 32],
            [value + 2; 32],
            1,
        )
        .expect("held identity")
    };
    let executable = VerifiedExecutableV1::new(
        file(1),
        ProcessFileKindV1::RegularFile,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .expect("executable");
    let cwd = VerifiedCwdV1::new(
        file(4),
        ProcessFileKindV1::Directory,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .expect("cwd");
    let binding = ProcessIdentityBindingV1::new(
        PrincipalId::new(identity(7)).unwrap(),
        AuthorityId::new(identity(8)).unwrap(),
        ProcessOwnerIdV1::new(identity(9)).unwrap(),
        ProcessAttemptIdV1::new(identity(10)).unwrap(),
        ProcessSessionIdV1::new(identity(11)).unwrap(),
        ProcessGenerationIdV1::new(identity(12)).unwrap(),
        CapabilityGrantId::new(identity(13)).unwrap(),
        SandboxId::new(identity(14)).unwrap(),
        HeldProcessTreeHandleV1::new(identity(15)).unwrap(),
    );
    let policy = ExecutablePolicyId::new(identity(16)).unwrap();
    let root = AllowedRootId::new(identity(17)).unwrap();
    let intent = ProcessIntentV1::new(
        ApprovalId::new(identity(18)).unwrap(),
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
        ProcessIoBoundsV1::new(4, 4, 8, 3, true).unwrap(),
        binding,
    )
    .unwrap();
    let authority = ProcessAuthorizationAuthorityV1::new(
        executable,
        policy,
        cwd,
        root,
        PrincipalId::new(identity(7)).unwrap(),
        AuthorityId::new(identity(8)).unwrap(),
        CapabilityGrantId::new(identity(13)).unwrap(),
        SandboxId::new(identity(14)).unwrap(),
        ApproverId::new(identity(19)).unwrap(),
        1,
        1,
        identity(20),
    )
    .unwrap();
    let boundary = authority.bind_call(intent.lifecycle_binding()).unwrap();
    let capability = boundary.issue_capability(&intent, 20).unwrap();
    let approval = boundary.approve(&intent, 20, true).unwrap();
    boundary
        .validate(intent, Some(&capability), Some(&approval), 10)
        .unwrap()
}

#[test]
fn sealed_host_settles_closed_platform_as_sticky_uncertain() {
    let mut host = test_host();
    let admission = EffectAdmission {
        permit_id: "rc0-pty-settlement".into(),
    };
    let first = host
        .dispatch(test_intent(), &admission)
        .expect("closed settlement");
    let replay = host
        .dispatch(test_intent(), &admission)
        .expect("exact replay");
    assert_eq!(
        first,
        ProcessHostOutcomeV1::State(ProcessLifecycleStateV1::Uncertain)
    );
    assert_eq!(replay, first);
}
