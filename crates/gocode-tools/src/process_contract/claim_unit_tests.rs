use crate::EffectAdmission;
use gocode_platform_ports::process::MonotonicDeadline;

use super::{
    ProcessClaimBindingV1, ProcessClaimInputV1, ProcessClaimRecordV1, ProcessContractErrorV1,
    ProcessLifecycleStateV1, journal::project_claim, orchestrator_test_support::Journal,
};

fn input() -> ProcessClaimInputV1 {
    ProcessClaimInputV1::new(
        &EffectAdmission {
            permit_id: "unit-permit".to_owned(),
        },
        [1; 32],
        ProcessClaimBindingV1::new([2; 16], [3; 16], [4; 16], [5; 16], [6; 16])
            .expect("marker-safe binding"),
        MonotonicDeadline::checked_after(10, 5).expect("valid deadline"),
    )
    .expect("outer admission")
}

#[test]
fn same_permit_changed_deadline_conflicts() {
    let admission = EffectAdmission {
        permit_id: "unit-permit".to_owned(),
    };
    let binding = ProcessClaimBindingV1::new([2; 16], [3; 16], [4; 16], [5; 16], [6; 16])
        .expect("marker-safe binding");
    let original = ProcessClaimInputV1::new(
        &admission,
        [1; 32],
        binding.clone(),
        MonotonicDeadline::checked_after(10, 5).expect("valid deadline"),
    )
    .expect("outer admission");
    let changed_deadline = ProcessClaimInputV1::new(
        &admission,
        [1; 32],
        binding,
        MonotonicDeadline::checked_after(10, 6).expect("valid deadline"),
    )
    .expect("outer admission");

    let mut journal = Journal::seeded();
    project_claim(&mut journal, &original).expect("first exact projection");

    assert_eq!(
        project_claim(&mut journal, &changed_deadline),
        Err(ProcessContractErrorV1::ClaimProjectionConflict)
    );
}

#[test]
fn first_projection_replays_once_and_changed_binding_or_digest_conflicts() {
    let admission = EffectAdmission {
        permit_id: "unit-permit".to_owned(),
    };
    let deadline = MonotonicDeadline::checked_after(10, 5).expect("valid deadline");
    let original = input();
    let changed_binding = ProcessClaimInputV1::new(
        &admission,
        [1; 32],
        ProcessClaimBindingV1::new([9; 16], [3; 16], [4; 16], [5; 16], [6; 16])
            .expect("marker-safe binding"),
        deadline,
    )
    .expect("outer admission");
    let changed_digest = ProcessClaimInputV1::new(
        &admission,
        [9; 32],
        ProcessClaimBindingV1::new([2; 16], [3; 16], [4; 16], [5; 16], [6; 16])
            .expect("marker-safe binding"),
        deadline,
    )
    .expect("outer admission");
    let mut journal = Journal::seeded();

    let (first, claimed) = project_claim(&mut journal, &original).expect("first projection");
    let (replay, replayed) = project_claim(&mut journal, &original).expect("exact replay");

    assert!(claimed);
    assert!(!replayed);
    assert_eq!(replay, first);
    assert_eq!((journal.records.len(), journal.cas_attempts()), (1, 1));
    for changed in [&changed_binding, &changed_digest] {
        assert_eq!(
            project_claim(&mut journal, changed),
            Err(ProcessContractErrorV1::ClaimProjectionConflict)
        );
    }
}

#[test]
fn claim_record_exposes_only_safe_key_and_state() {
    let record = ProcessClaimRecordV1::claimed(&input());

    assert_eq!(record.state(), ProcessLifecycleStateV1::Claimed);
    assert_eq!(record.settlement(), None);
}

#[test]
fn claim_record_rejects_ordinary_terminal_transition() {
    let mut record = ProcessClaimRecordV1::claimed(&input());

    assert_eq!(
        record.transition(ProcessLifecycleStateV1::Completed),
        Err(ProcessContractErrorV1::InvalidLifecycleTransition)
    );
    assert_eq!(
        record.transition(ProcessLifecycleStateV1::Uncertain),
        Err(ProcessContractErrorV1::InvalidLifecycleTransition)
    );
}
