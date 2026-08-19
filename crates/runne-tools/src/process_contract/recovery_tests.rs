use crate::EffectAdmission;
use runne_platform_ports::process::{
    MonotonicDeadline, ProcessOwnerVerificationV1, ProcessTreeCleanupV1,
};

use super::{
    ProcessClaimBindingV1, ProcessClaimInputV1, ProcessClaimRecordV1, ProcessContractErrorV1,
    ProcessLifecycleStateV1, ProcessMonotonicTimingDispositionV1, ProcessOutputEvidenceV1,
    ProcessSettlementProofV1, ProcessTerminalSettlementV1, ProcessUncertainReasonV1,
    VirtualProcessTreeFixtureV1, journal::recover_after_reopen, orchestrator_test_support::Journal,
};

#[test]
fn reopen_claimed_launching_running_terminating_become_uncertain_without_calls() {
    for state in [
        ProcessLifecycleStateV1::Claimed,
        ProcessLifecycleStateV1::Launching,
        ProcessLifecycleStateV1::Running,
        ProcessLifecycleStateV1::Terminating,
    ] {
        let input = input();
        let mut journal = Journal::seeded();
        journal
            .records
            .insert("reopen-permit".to_owned(), record_in(state, &input));
        let platform = VirtualProcessTreeFixtureV1::new();

        let recovered = recover_after_reopen(&mut journal, input.key())
            .expect("recovery result")
            .expect("persisted claim");
        let settlement = recovered.settlement().expect("uncertain settlement");

        assert_eq!(recovered.state(), ProcessLifecycleStateV1::Uncertain);
        assert_eq!(
            settlement.proof(),
            &ProcessSettlementProofV1::Uncertain(ProcessUncertainReasonV1::RecoveryRequired)
        );
        assert_eq!(
            settlement.timing(),
            ProcessMonotonicTimingDispositionV1::TimingUncertain
        );
        assert_eq!(
            settlement.owner_verification(),
            ProcessOwnerVerificationV1::Unavailable
        );
        assert_eq!(settlement.tree_cleanup(), ProcessTreeCleanupV1::Unavailable);
        assert_eq!(settlement.output(), &ProcessOutputEvidenceV1::empty());
        assert!(platform.call_log().expect("healthy fixture").is_empty());
    }
}

#[test]
fn reopen_terminal_returns_prior_unchanged() {
    let input = input();
    let mut record = ProcessClaimRecordV1::claimed(&input);
    record
        .transition(ProcessLifecycleStateV1::Launching)
        .expect("launching state");
    record
        .commit_settlement(uncertain_settlement(&input))
        .expect("terminal settlement");
    let mut journal = Journal::seeded();
    journal
        .records
        .insert("reopen-permit".to_owned(), record.clone());

    let recovered = recover_after_reopen(&mut journal, input.key())
        .expect("recovery result")
        .expect("persisted terminal");

    assert_eq!(recovered, record);
    assert_eq!(journal.cas_attempts(), 0);
}

#[test]
fn recovery_cas_conflict_does_not_redispatch_or_retry() {
    let input = input();
    let mut journal = Journal::seeded();
    journal.records.insert(
        "reopen-permit".to_owned(),
        ProcessClaimRecordV1::claimed(&input),
    );
    journal.reject_terminal_cas();
    let platform = VirtualProcessTreeFixtureV1::new();

    assert_eq!(
        recover_after_reopen(&mut journal, input.key()),
        Err(ProcessContractErrorV1::ClaimProjectionConflict)
    );
    assert_eq!(journal.cas_attempts(), 1);
    assert!(platform.call_log().expect("healthy fixture").is_empty());
}

fn input() -> ProcessClaimInputV1 {
    ProcessClaimInputV1::new(
        &EffectAdmission {
            permit_id: "reopen-permit".to_owned(),
        },
        [1; 32],
        ProcessClaimBindingV1::new([2; 16], [3; 16], [4; 16], [5; 16], [6; 16])
            .expect("marker-safe binding"),
        MonotonicDeadline::checked_after(10, 5).expect("valid deadline"),
    )
    .expect("outer admission")
}

fn record_in(state: ProcessLifecycleStateV1, input: &ProcessClaimInputV1) -> ProcessClaimRecordV1 {
    let mut record = ProcessClaimRecordV1::claimed(input);
    for next in [
        ProcessLifecycleStateV1::Launching,
        ProcessLifecycleStateV1::Running,
        ProcessLifecycleStateV1::Terminating,
    ] {
        if record.state() == state {
            break;
        }
        record
            .transition(next)
            .expect("valid nonterminal transition");
    }
    record
}

fn uncertain_settlement(input: &ProcessClaimInputV1) -> ProcessTerminalSettlementV1 {
    ProcessTerminalSettlementV1::new(
        input.binding(),
        ProcessSettlementProofV1::Uncertain(ProcessUncertainReasonV1::EvidenceUnavailable),
        ProcessOutputEvidenceV1::empty(),
        ProcessMonotonicTimingDispositionV1::WithinDeadline,
        ProcessTreeCleanupV1::Unavailable,
        ProcessOwnerVerificationV1::Unavailable,
    )
    .expect("valid uncertain settlement")
}
