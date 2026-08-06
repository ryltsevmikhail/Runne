use super::{
    HeldFileIdentityV1, HeldProcessTreeHandleV1, MonotonicDeadline, MonotonicDeadlineErrorV1,
    NoProcessStartedEvidenceV1, ProcessAttemptIdV1, ProcessFileKindV1, ProcessGenerationIdV1,
    ProcessLaunchEvidenceV1, ProcessLaunchOutcomeV1, ProcessLifecycleBindingV1, ProcessOwnerIdV1,
    ProcessOwnerVerificationV1, ProcessPlatformFailure, ProcessPlatformPort,
    ProcessPlatformRequestV1, ProcessSessionIdV1, ProcessStubDisposition, ProcessSymlinkProofV1,
    ProcessTerminalDispositionV1, ProcessTerminalEvidenceV1, ProcessTreeCleanupV1, VerifiedCwdV1,
    VerifiedExecutableV1,
};

fn held_file_identity() -> HeldFileIdentityV1 {
    HeldFileIdentityV1::new([1; 16], [2; 32], [3; 32], [4; 32], 1).expect("valid identity")
}

fn lifecycle_binding() -> ProcessLifecycleBindingV1 {
    ProcessLifecycleBindingV1::new(
        ProcessOwnerIdV1::new([1; 16]).expect("valid owner"),
        ProcessAttemptIdV1::new([2; 16]).expect("valid attempt"),
        ProcessSessionIdV1::new([3; 16]).expect("valid session"),
        ProcessGenerationIdV1::new([4; 16]).expect("valid generation"),
        HeldProcessTreeHandleV1::new([5; 16]).expect("valid tree handle"),
    )
}

fn request() -> ProcessPlatformRequestV1 {
    let executable = VerifiedExecutableV1::new(
        held_file_identity(),
        ProcessFileKindV1::RegularFile,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .expect("valid executable");
    let cwd = VerifiedCwdV1::new(
        held_file_identity(),
        ProcessFileKindV1::Directory,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .expect("valid cwd");
    ProcessPlatformRequestV1::new([5; 32], executable, cwd).expect("valid request")
}

#[test]
fn constructors_reject_zero_identity_version() {
    assert!(HeldFileIdentityV1::new([1; 16], [2; 32], [3; 32], [4; 32], 0).is_err());
}

#[test]
fn constructors_reject_empty_held_token() {
    assert!(HeldFileIdentityV1::new([0; 16], [2; 32], [3; 32], [4; 32], 1).is_err());
}

#[test]
fn constructors_reject_non_regular_executable() {
    assert!(
        VerifiedExecutableV1::new(
            held_file_identity(),
            ProcessFileKindV1::Directory,
            ProcessSymlinkProofV1::VerifiedNotSymlink,
        )
        .is_err()
    );
}

#[test]
fn constructors_reject_symlink_proof_failure() {
    assert!(
        VerifiedExecutableV1::new(
            held_file_identity(),
            ProcessFileKindV1::RegularFile,
            ProcessSymlinkProofV1::ProofUnavailable,
        )
        .is_err()
    );
}

#[test]
fn constructors_reject_zero_tree_handle() {
    assert!(HeldProcessTreeHandleV1::new([0; 16]).is_err());
}

#[test]
fn lifecycle_binding_keeps_distinct_owner_session_and_generation() {
    let owner = ProcessOwnerIdV1::new([1; 16]).expect("valid owner");
    let attempt = ProcessAttemptIdV1::new([2; 16]).expect("valid attempt");
    let session = ProcessSessionIdV1::new([3; 16]).expect("valid session");
    let generation = ProcessGenerationIdV1::new([4; 16]).expect("valid generation");
    let binding = ProcessLifecycleBindingV1::new(
        owner.clone(),
        attempt,
        session.clone(),
        generation.clone(),
        HeldProcessTreeHandleV1::new([5; 16]).expect("valid tree handle"),
    );

    assert_eq!(binding.owner(), &owner);
    assert_eq!(binding.session(), &session);
    assert_eq!(binding.generation(), &generation);
}

#[test]
fn request_exposes_verified_held_identities_for_revalidation() {
    let request = request();

    assert_eq!(request.executable().identity().identity_version(), 1);
    assert_eq!(request.cwd().identity().identity_version(), 1);
}

#[test]
fn deadline_retains_start_and_expiry_and_rejects_invalid_ticks() {
    let deadline = MonotonicDeadline::checked_after(7, 3).expect("bounded deadline");

    assert_eq!(deadline.started_at(), 7);
    assert_eq!(deadline.expires_at(), 10);
    assert!(!deadline.is_reached(9).expect("forward clock"));
    assert!(deadline.is_reached(10).expect("exact boundary"));
    assert_eq!(
        MonotonicDeadline::checked_after(7, 0),
        Err(MonotonicDeadlineErrorV1::ZeroDeadlineBudget)
    );
    assert_eq!(
        MonotonicDeadline::checked_after(u64::MAX, 1),
        Err(MonotonicDeadlineErrorV1::MonotonicDeadlineOverflow)
    );
    assert_eq!(
        deadline.is_reached(6),
        Err(MonotonicDeadlineErrorV1::MonotonicClockRegressed)
    );
}

#[test]
fn evidence_retains_exact_lifecycle_binding() {
    let binding = lifecycle_binding();
    let no_start = NoProcessStartedEvidenceV1::new(&binding, [5; 32]).expect("valid no-start");
    let launch = ProcessLaunchEvidenceV1::new(&binding, [6; 32]).expect("valid launch evidence");
    let terminal = ProcessTerminalEvidenceV1::new(
        &binding,
        ProcessTerminalDispositionV1::Completed,
        ProcessOwnerVerificationV1::Verified,
        ProcessTreeCleanupV1::Verified,
        [7; 32],
    )
    .expect("valid terminal evidence");

    assert_eq!(no_start.binding(), &binding);
    assert_eq!(launch.binding(), &binding);
    assert_eq!(terminal.binding(), &binding);
    assert_eq!(
        terminal.owner_verification(),
        ProcessOwnerVerificationV1::Verified
    );
    assert_eq!(terminal.tree_cleanup(), ProcessTreeCleanupV1::Verified);
    assert_eq!(
        (no_start.owner_verification(), no_start.tree_cleanup()),
        (
            ProcessOwnerVerificationV1::NotApplicable,
            ProcessTreeCleanupV1::NotApplicable
        )
    );
}

struct FakePort;
struct PrivatePrepared;

impl ProcessPlatformPort for FakePort {
    type Prepared = PrivatePrepared;

    fn validate_and_prepare(
        &self,
        _request: &ProcessPlatformRequestV1,
        _deadline: super::MonotonicDeadline,
    ) -> Result<Self::Prepared, ProcessPlatformFailure> {
        Ok(PrivatePrepared)
    }

    fn launch(
        &self,
        _prepared: Self::Prepared,
        binding: &ProcessLifecycleBindingV1,
        _deadline: super::MonotonicDeadline,
    ) -> Result<ProcessLaunchOutcomeV1, ProcessPlatformFailure> {
        Ok(ProcessLaunchOutcomeV1::NoProcessStarted(
            super::NoProcessStartedEvidenceV1::new(binding, [8; 32])?,
        ))
    }

    fn terminate(
        &self,
        _binding: &ProcessLifecycleBindingV1,
        _deadline: super::MonotonicDeadline,
    ) -> Result<ProcessTerminalEvidenceV1, ProcessPlatformFailure> {
        Err(ProcessPlatformFailure::Disposition(
            ProcessStubDisposition::NotQualified,
        ))
    }
}

#[test]
fn adapter_private_prepared_value_only_crosses_its_own_validation_boundary() {
    let port = FakePort;
    let binding = lifecycle_binding();
    let prepared = port
        .validate_and_prepare(
            &request(),
            super::MonotonicDeadline::checked_after(1, 1).unwrap(),
        )
        .expect("prepared by adapter");
    let outcome = port
        .launch(
            prepared,
            &binding,
            super::MonotonicDeadline::checked_after(1, 1).unwrap(),
        )
        .expect("launch outcome");

    assert!(matches!(
        outcome,
        ProcessLaunchOutcomeV1::NoProcessStarted(_)
    ));
}
