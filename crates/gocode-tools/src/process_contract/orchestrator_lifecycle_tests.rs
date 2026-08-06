use super::{
    ProcessDispatchOutcomeV1, ProcessLifecycleStateV1, ProcessOrchestratorV1, VirtualGraceScriptV1,
    VirtualProcessCallV1, VirtualProcessTreeFixtureV1,
    orchestrator_test_support::{
        Cancel, CancelSequence, Clock, Journal, OutputSource, admission, input,
    },
};

#[test]
fn cancellation_before_dispatch_is_denied_without_claim_or_platform_call() {
    let mut journal = Journal::default();
    let platform = VirtualProcessTreeFixtureV1::new();

    assert_eq!(
        ProcessOrchestratorV1::new()
            .dispatch_input(
                input(2),
                &admission(),
                &mut journal,
                &platform,
                &platform,
                &mut OutputSource::terminal(),
                &Clock::new(&[0]),
                &Cancel(true)
            )
            .unwrap(),
        ProcessDispatchOutcomeV1::Denied
    );
    assert!(journal.records.is_empty());
    assert!(platform.call_log().expect("healthy fixture").is_empty());
}

#[test]
fn cancellation_during_running_uses_exact_forced_cleanup_sequence() {
    let mut journal = Journal::seeded();
    let platform = VirtualProcessTreeFixtureV1::with_descendants(2, 3);

    assert!(matches!(
        ProcessOrchestratorV1::new()
            .dispatch_input(
                input(8),
                &admission(),
                &mut journal,
                &platform,
                &platform,
                &mut OutputSource::terminal(),
                &Clock::new(&[0, 0]),
                &CancelSequence::new(&[false, true])
            )
            .unwrap(),
        ProcessDispatchOutcomeV1::Terminal(_)
    ));
    assert_eq!(
        (
            platform.descendants().expect("healthy fixture"),
            platform.unrelated_descendants().expect("healthy fixture"),
        ),
        (0, 3)
    );
    assert_eq!(
        platform.call_log().expect("healthy fixture"),
        forced_calls()
    );
}

#[test]
fn terminal_commit_failure_keeps_terminating_state_without_receipt() {
    let mut journal = Journal::seeded();
    journal.fail_terminal_commit();
    let platform = VirtualProcessTreeFixtureV1::new();

    assert_eq!(
        ProcessOrchestratorV1::new().dispatch_input(
            input(10),
            &admission(),
            &mut journal,
            &platform,
            &platform,
            &mut OutputSource::terminal(),
            &Clock::new(&[0, 0, 1]),
            &Cancel(false),
        ),
        Err(super::ProcessContractErrorV1::TerminalCommitFailed)
    );
    let record = journal
        .records
        .get("sealed-permit")
        .expect("claimed record");
    assert_eq!(record.state(), ProcessLifecycleStateV1::Terminating);
    assert_ne!(record.state(), ProcessLifecycleStateV1::Completed);
    assert_eq!(record.settlement(), None);
    assert_eq!(
        platform.call_log().expect("healthy fixture"),
        forced_calls()
    );
}

#[test]
fn graceful_completion_avoids_force_and_replay_returns_same_safe_receipt() {
    let mut journal = Journal::seeded();
    let platform = VirtualProcessTreeFixtureV1::with_descendants(2, 3);
    platform
        .set_grace_script(VirtualGraceScriptV1::Complete)
        .expect("healthy fixture");
    let input = input(9);
    let orchestrator = ProcessOrchestratorV1::new();

    let first_receipt = match orchestrator
        .dispatch_input(
            input.clone(),
            &admission(),
            &mut journal,
            &platform,
            &platform,
            &mut OutputSource::terminal(),
            &Clock::new(&[0, 0, 1]),
            &Cancel(false),
        )
        .unwrap()
    {
        ProcessDispatchOutcomeV1::Terminal(receipt) => receipt,
        outcome => panic!("expected terminal dispatch, got {outcome:?}"),
    };
    assert_eq!(
        platform.call_log().expect("healthy fixture"),
        graceful_calls()
    );
    let receipt = match orchestrator
        .dispatch_input(
            input,
            &admission(),
            &mut journal,
            &platform,
            &platform,
            &mut OutputSource::terminal(),
            &Clock::new(&[0]),
            &Cancel(false),
        )
        .unwrap()
    {
        ProcessDispatchOutcomeV1::Terminal(receipt) => receipt,
        outcome => panic!("expected terminal replay, got {outcome:?}"),
    };
    assert!(matches!(
        receipt.settlement().proof(),
        super::ProcessSettlementProofV1::Completed(evidence)
            if evidence.disposition()
                == gocode_platform_ports::process::ProcessTerminalDispositionV1::Completed
                && evidence.evidence_digest() == &[4; 32]
    ));
    assert_eq!(receipt, first_receipt);
    assert_eq!(
        (
            platform.descendants().expect("healthy fixture"),
            platform.unrelated_descendants().expect("healthy fixture"),
        ),
        (0, 3)
    );
    assert_eq!(
        platform.call_log().expect("healthy fixture"),
        graceful_calls()
    );
}

#[test]
fn timeout_budget_is_relative_to_dispatch_start() {
    let mut journal = Journal::seeded();
    let platform = VirtualProcessTreeFixtureV1::new();

    assert_eq!(
        ProcessOrchestratorV1::new()
            .dispatch_input(
                input(11),
                &admission(),
                &mut journal,
                &platform,
                &platform,
                &mut OutputSource::terminal(),
                &Clock::new(&[100, 100, 100]),
                &Cancel(false),
            )
            .expect("relative budget remains live"),
        ProcessDispatchOutcomeV1::State(ProcessLifecycleStateV1::Running)
    );
}

#[test]
fn exact_deadline_boundary_is_expired() {
    let mut journal = Journal::seeded();
    let platform = VirtualProcessTreeFixtureV1::new();

    assert!(matches!(
        ProcessOrchestratorV1::new()
            .dispatch_input(
                input(12),
                &admission(),
                &mut journal,
                &platform,
                &platform,
                &mut OutputSource::terminal(),
                &Clock::new(&[10, 10, 11]),
                &Cancel(false),
            )
            .expect("boundary triggers termination"),
        ProcessDispatchOutcomeV1::Terminal(_)
    ));
}

#[test]
fn deadline_overflow_denies_before_claim() {
    let mut journal = Journal::default();
    let platform = VirtualProcessTreeFixtureV1::new();
    let mut dispatch = input(13);
    dispatch.timeout_ticks = 2;

    assert_eq!(
        ProcessOrchestratorV1::new()
            .dispatch_input(
                dispatch,
                &admission(),
                &mut journal,
                &platform,
                &platform,
                &mut OutputSource::terminal(),
                &Clock::new(&[u64::MAX]),
                &Cancel(false),
            )
            .expect("overflow denies"),
        ProcessDispatchOutcomeV1::Denied
    );
    assert!(journal.records.is_empty());
    assert!(platform.call_log().expect("healthy fixture").is_empty());
}

#[test]
fn clock_regression_fails_closed() {
    let mut journal = Journal::seeded();
    let platform = VirtualProcessTreeFixtureV1::new();

    assert_eq!(
        ProcessOrchestratorV1::new()
            .dispatch_input(
                input(14),
                &admission(),
                &mut journal,
                &platform,
                &platform,
                &mut OutputSource::terminal(),
                &Clock::new(&[10, 10, 9]),
                &Cancel(false),
            )
            .expect("regression closes the claimed dispatch"),
        ProcessDispatchOutcomeV1::State(ProcessLifecycleStateV1::Uncertain)
    );
}

#[test]
fn grace_overflow_never_extends_wait() {
    let source = include_str!("orchestrator_termination.rs");

    assert!(!source.contains("saturating_add"));
    assert!(source.contains("MonotonicDeadline::current"));
}

fn graceful_calls() -> Vec<VirtualProcessCallV1> {
    vec![
        VirtualProcessCallV1::ValidateAndPrepare,
        VirtualProcessCallV1::Launch,
        VirtualProcessCallV1::RequestGraceful,
        VirtualProcessCallV1::WaitForGrace,
    ]
}

fn forced_calls() -> Vec<VirtualProcessCallV1> {
    let mut calls = graceful_calls();
    calls.push(VirtualProcessCallV1::Terminate);
    calls
}
