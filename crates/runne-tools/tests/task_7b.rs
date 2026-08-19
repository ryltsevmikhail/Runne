use runne_tools::{
    AllowedRootId, ApprovalId, ApproverId, AuthorityId, BoundedArgvV1, CapabilityGrantId,
    EffectAdmission, ExecutablePolicyId, ExplicitEnvironmentV1, HeldFileIdentityV1,
    HeldProcessTreeHandleV1, InputBoundsV1, PortableUtf8V1, PrincipalId, ProcessApprovalV1,
    ProcessAttemptIdV1, ProcessAuthorizationAdvanceV1, ProcessAuthorizationAuthorityV1,
    ProcessCapabilityId, ProcessCapabilityV1, ProcessClaimJournalMemorySnapshotV1,
    ProcessClaimJournalMemoryV1, ProcessContractError, ProcessContractErrorV1,
    ProcessContractHostSnapshotV1, ProcessContractHostV1, ProcessFileKindV1, ProcessGenerationIdV1,
    ProcessHostOutcomeV1, ProcessIdentityBindingV1, ProcessIntentDigestV1, ProcessIntentV1,
    ProcessIoBoundsV1, ProcessLifecycleStateV1, ProcessOwnerIdV1, ProcessPlatformTargetV1,
    ProcessSessionIdV1, ProcessStubDisposition, ProcessSymlinkProofV1, ProcessTerminalResultV1,
    ProcessUncertainReasonV1, SandboxId, SandboxQualificationProbe, StdinPolicyV1,
    ValidatedProcessIntentV1, VerifiedCwdV1, VerifiedExecutableV1, production_sandbox_probe,
};

fn id(value: u8) -> [u8; 16] {
    [value; 16]
}

struct QualifiedProbe;

impl SandboxQualificationProbe for QualifiedProbe {
    fn qualify(&self) -> Result<(), ProcessStubDisposition> {
        Ok(())
    }
}

#[test]
fn crate_root_reexports_compile() {
    macro_rules! root_types {
        ($($ty:ty),+ $(,)?) => {
            $(let _: Option<$ty> = None;)+
        };
    }

    root_types!(
        ProcessApprovalV1,
        ProcessAuthorizationAuthorityV1,
        ProcessCapabilityId,
        ProcessCapabilityV1,
        ProcessClaimJournalMemorySnapshotV1,
        ProcessContractError,
        ProcessContractErrorV1,
        ProcessContractHostSnapshotV1,
        ProcessIntentDigestV1,
        ProcessTerminalResultV1,
        ProcessUncertainReasonV1,
    );
    let _: Option<ProcessAuthorizationAdvanceV1<'static>> = None;
}

fn validated_intent() -> ValidatedProcessIntentV1 {
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
        file(4),
        ProcessFileKindV1::Directory,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .unwrap();
    let binding = ProcessIdentityBindingV1::new(
        PrincipalId::new(id(7)).unwrap(),
        AuthorityId::new(id(8)).unwrap(),
        ProcessOwnerIdV1::new(id(9)).unwrap(),
        ProcessAttemptIdV1::new(id(10)).unwrap(),
        ProcessSessionIdV1::new(id(11)).unwrap(),
        ProcessGenerationIdV1::new(id(12)).unwrap(),
        CapabilityGrantId::new(id(13)).unwrap(),
        SandboxId::new(id(14)).unwrap(),
        HeldProcessTreeHandleV1::new(id(15)).unwrap(),
    );
    let policy = ExecutablePolicyId::new(id(16)).unwrap();
    let root = AllowedRootId::new(id(17)).unwrap();
    let intent = ProcessIntentV1::new(
        ApprovalId::new(id(18)).unwrap(),
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
        binding.clone(),
    )
    .unwrap();
    let authority = ProcessAuthorizationAuthorityV1::new(
        executable,
        policy,
        cwd,
        root,
        PrincipalId::new(id(7)).unwrap(),
        AuthorityId::new(id(8)).unwrap(),
        CapabilityGrantId::new(id(13)).unwrap(),
        SandboxId::new(id(14)).unwrap(),
        ApproverId::new(id(19)).unwrap(),
        1,
        1,
        id(20),
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
fn probes_distinguish_test_qualification_from_production_failure() {
    assert_eq!(QualifiedProbe.qualify(), Ok(()));
    assert_eq!(
        production_sandbox_probe().qualify(),
        Err(ProcessStubDisposition::NotQualified)
    );
}

#[test]
fn host_settles_closed_linux_stub_as_sticky_uncertain_on_exact_replay() {
    let mut host = ProcessContractHostV1::new(
        ProcessClaimJournalMemoryV1::new(),
        ProcessPlatformTargetV1::Linux,
        100,
    );
    let admission = EffectAdmission {
        permit_id: "task-7b-permit".to_owned(),
    };

    let first = host.dispatch(validated_intent(), &admission).unwrap();
    let replay = host.dispatch(validated_intent(), &admission).unwrap();

    assert_eq!(
        first,
        ProcessHostOutcomeV1::State(ProcessLifecycleStateV1::Uncertain)
    );
    assert_eq!(replay, first);
}

#[test]
fn reopened_host_replays_the_exact_uncertain_claim_without_redispatch() {
    let mut host = ProcessContractHostV1::new(
        ProcessClaimJournalMemoryV1::new(),
        ProcessPlatformTargetV1::Linux,
        100,
    );
    let admission = EffectAdmission {
        permit_id: "task-7b-recovery-permit".to_owned(),
    };

    let first = host.dispatch(validated_intent(), &admission).unwrap();
    let snapshot = host.snapshot();
    let mut reopened = ProcessContractHostV1::reopen(snapshot);
    let replay = reopened.dispatch(validated_intent(), &admission).unwrap();

    assert_eq!(
        first,
        ProcessHostOutcomeV1::State(ProcessLifecycleStateV1::Uncertain)
    );
    assert_eq!(replay, first);
}
