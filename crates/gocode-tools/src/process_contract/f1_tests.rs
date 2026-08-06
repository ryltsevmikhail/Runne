use gocode_platform_ports::process::{ProcessOwnerVerificationV1, ProcessTreeCleanupV1};

use super::{
    ProcessClaimInputV1, ProcessClaimRecordV1, ProcessContractErrorV1, ProcessDispatchOutcomeV1,
    ProcessLifecycleStateV1, ProcessMonotonicTimingDispositionV1, ProcessOrchestratorV1,
    ProcessSettlementProofV1, ProcessUncertainReasonV1, VirtualGraceScriptV1,
    VirtualLaunchScriptV1, VirtualProcessTreeFixtureV1,
    orchestrator_test_support::{
        Cancel, CancelSequence, Clock, Journal, OutputSource, admission, input,
    },
};

#[test]
fn no_start_has_not_applicable_dispositions_and_no_held_tree() {
    let mut journal = Journal::seeded();
    let platform = VirtualProcessTreeFixtureV1::new();
    platform
        .set_launch_script(VirtualLaunchScriptV1::NoProcessStarted)
        .expect("healthy fixture");

    let outcome = ProcessOrchestratorV1::new()
        .dispatch_input(
            input(40),
            &admission(),
            &mut journal,
            &platform,
            &platform,
            &mut OutputSource::terminal(),
            &Clock::new(&[0]),
            &Cancel(false),
        )
        .expect("no-start settlement");

    assert_eq!(outcome.state(), Some(ProcessLifecycleStateV1::NotStarted));
    assert!(!platform.has_held_binding().expect("healthy fixture"));
    let settlement = journal.records["sealed-permit"]
        .settlement()
        .expect("settlement");
    assert_eq!(
        (settlement.owner_verification(), settlement.tree_cleanup()),
        (
            ProcessOwnerVerificationV1::NotApplicable,
            ProcessTreeCleanupV1::NotApplicable
        )
    );
}

#[test]
fn owner_mismatch_and_unverified_descendants_settle_uncertain() {
    for (owner, cleanup) in [
        (
            ProcessOwnerVerificationV1::Mismatch,
            ProcessTreeCleanupV1::Unverified,
        ),
        (
            ProcessOwnerVerificationV1::Unavailable,
            ProcessTreeCleanupV1::Unverified,
        ),
    ] {
        let mut journal = Journal::seeded();
        let platform = terminal_platform(owner, cleanup);

        let outcome = ProcessOrchestratorV1::new()
            .dispatch_input(
                input(41),
                &admission(),
                &mut journal,
                &platform,
                &platform,
                &mut OutputSource::terminal(),
                &Clock::new(&[0, 0, 1]),
                &Cancel(false),
            )
            .expect("uncertain settlement");

        assert_eq!(
            outcome,
            ProcessDispatchOutcomeV1::State(ProcessLifecycleStateV1::Uncertain)
        );
        assert!(matches!(
            journal.records["sealed-permit"]
                .settlement()
                .expect("settlement")
                .proof(),
            ProcessSettlementProofV1::Uncertain(_)
        ));
    }
}

#[test]
fn deadline_cancellation_and_regression_have_distinct_timing_dispositions() {
    let deadline = dispatch_terminal(&Clock::new(&[0, 0, 1]), &Cancel(false));
    assert_eq!(
        deadline.timing(),
        ProcessMonotonicTimingDispositionV1::DeadlineReached
    );

    let cancellation =
        dispatch_terminal(&Clock::new(&[0, 0]), &CancelSequence::new(&[false, true]));
    assert_eq!(
        cancellation.timing(),
        ProcessMonotonicTimingDispositionV1::CancellationObservedBeforeDeadline
    );

    let mut journal = Journal::seeded();
    let platform = VirtualProcessTreeFixtureV1::new();
    let outcome = ProcessOrchestratorV1::new()
        .dispatch_input(
            input(42),
            &admission(),
            &mut journal,
            &platform,
            &platform,
            &mut OutputSource::terminal(),
            &Clock::new(&[10, 10, 9]),
            &Cancel(false),
        )
        .expect("timing uncertainty settles");
    assert_eq!(outcome.state(), Some(ProcessLifecycleStateV1::Uncertain));
    let settlement = journal.records["sealed-permit"]
        .settlement()
        .expect("settlement");
    assert_eq!(
        settlement.timing(),
        ProcessMonotonicTimingDispositionV1::TimingUncertain
    );
    assert_eq!(
        settlement.proof(),
        &ProcessSettlementProofV1::Uncertain(ProcessUncertainReasonV1::TimingUnavailable)
    );
}

#[test]
fn terminal_metadata_is_cas_derived_and_replay_is_stable() {
    let mut journal = Journal::seeded();
    let platform = completed_platform();
    let request = input(43);
    let orchestrator = ProcessOrchestratorV1::new();

    let first = orchestrator
        .dispatch_input(
            request.clone(),
            &admission(),
            &mut journal,
            &platform,
            &platform,
            &mut OutputSource::terminal(),
            &Clock::new(&[0, 0, 1]),
            &Cancel(false),
        )
        .expect("terminal settlement");
    assert_eq!(first.state(), Some(ProcessLifecycleStateV1::Completed));
    let before = journal.records["sealed-permit"].clone();
    let settlement = before.settlement().expect("terminal settlement");
    assert_eq!(settlement.revision(), before.revision());
    assert_eq!(settlement.sequence(), before.settlement_sequence());

    let replay = orchestrator
        .dispatch_input(
            request,
            &admission(),
            &mut journal,
            &platform,
            &platform,
            &mut OutputSource::terminal(),
            &Clock::new(&[0]),
            &Cancel(false),
        )
        .expect("terminal replay");
    assert_eq!(replay.state(), Some(ProcessLifecycleStateV1::Completed));
    assert_eq!(journal.records["sealed-permit"], before);
}

#[test]
fn terminal_cas_conflict_fences_the_effect_and_replay() {
    let mut journal = Journal::seeded();
    journal.reject_terminal_cas();
    let platform = completed_platform();
    let request = input(45);
    let orchestrator = ProcessOrchestratorV1::new();
    let mut output = OutputSource::terminal();

    assert_eq!(
        orchestrator.dispatch_input(
            request.clone(),
            &admission(),
            &mut journal,
            &platform,
            &platform,
            &mut output,
            &Clock::new(&[0, 0, 1]),
            &Cancel(false),
        ),
        Err(ProcessContractErrorV1::ClaimProjectionConflict)
    );
    let calls = platform.call_log().expect("healthy fixture");
    let reads = output.reads();

    assert_eq!(
        orchestrator
            .dispatch_input(
                request,
                &admission(),
                &mut journal,
                &platform,
                &platform,
                &mut output,
                &Clock::new(&[0]),
                &Cancel(false),
            )
            .expect("CAS-conflicted replay is fenced"),
        ProcessDispatchOutcomeV1::State(ProcessLifecycleStateV1::Terminating)
    );
    assert_eq!(platform.call_log().expect("healthy fixture"), calls);
    assert_eq!(output.reads(), reads);
}

#[test]
fn metadata_revision_overflow_leaves_claim_unchanged() {
    let dispatch = input(46);
    let claim = ProcessClaimInputV1::new(
        &admission(),
        dispatch.digest,
        dispatch.claim_binding,
        gocode_platform_ports::process::MonotonicDeadline::checked_after(0, 1)
            .expect("valid deadline"),
    )
    .expect("valid claim");
    let mut record = ProcessClaimRecordV1::claimed(&claim);
    record.set_test_metadata(u64::MAX, record.settlement_sequence());
    let before = record.clone();

    assert_eq!(
        record.transition(ProcessLifecycleStateV1::Launching),
        Err(ProcessContractErrorV1::MetadataOverflow)
    );
    assert_eq!(record, before);
}

fn terminal_platform(
    owner: ProcessOwnerVerificationV1,
    cleanup: ProcessTreeCleanupV1,
) -> VirtualProcessTreeFixtureV1 {
    let platform = VirtualProcessTreeFixtureV1::new();
    platform
        .set_grace_script(VirtualGraceScriptV1::Complete)
        .expect("healthy fixture");
    platform
        .set_terminal_verification(owner, cleanup)
        .expect("healthy fixture");
    platform
}

fn completed_platform() -> VirtualProcessTreeFixtureV1 {
    let platform = VirtualProcessTreeFixtureV1::new();
    platform
        .set_grace_script(VirtualGraceScriptV1::Complete)
        .expect("healthy fixture");
    platform
}

fn dispatch_terminal<C>(clock: &Clock<'_>, cancellation: &C) -> super::ProcessTerminalSettlementV1
where
    C: super::ProcessCancellationTokenV1,
{
    let mut journal = Journal::seeded();
    let platform = completed_platform();
    let outcome = ProcessOrchestratorV1::new()
        .dispatch_input(
            input(44),
            &admission(),
            &mut journal,
            &platform,
            &platform,
            &mut OutputSource::terminal(),
            clock,
            cancellation,
        )
        .expect("terminal settlement");
    assert!(matches!(outcome, ProcessDispatchOutcomeV1::Terminal(_)));
    journal.records["sealed-permit"]
        .settlement()
        .expect("terminal settlement")
}
