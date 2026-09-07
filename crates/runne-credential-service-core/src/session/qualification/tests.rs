use super::allocation::{QualificationAllocator, SystemQualificationAllocator};
use super::clocks::{LockedCredentialServiceClocks, QualificationClockSource};
use super::resources::QualificationResourceBudget;
use super::state::{QualificationState, StartCommitment};

mod stage;

const FULL_TRANSFER_BYTES: usize = 524_300 + 8_192;

#[test]
fn gate_a_keeps_qualification_out_of_the_production_runtime_path() {
    for source in [
        include_str!("../runtime.rs"),
        include_str!("../validation.rs"),
    ] {
        assert!(
            !source.contains("stage_qualification_request")
                && !source.contains("ServiceQualification"),
            "Gate A must keep qualification ingress out of the immediate runtime path"
        );
    }
}

#[test]
fn start_reservation_stays_charged_until_outside_owner_drops() {
    let budget = QualificationResourceBudget::new_for_test();
    let mut state = QualificationState::empty();
    let pending = state
        .begin(StartCommitment::for_test(13, 19), &budget)
        .expect("valid start reserves the declared logical input bytes");

    assert!(state.is_allocating());
    assert_eq!(budget.usage_for_test(), (1, 32, 0));

    drop(pending);
    assert_eq!(budget.usage_for_test(), (0, 0, 0));
}

#[test]
fn rejected_start_does_not_leave_a_partial_charge() {
    let budget = QualificationResourceBudget::new_for_test();
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(
            QualificationState::empty()
                .begin(StartCommitment::for_test(524_300, 8_192), &budget)
                .expect("four full transfers fit exactly"),
        );
    }

    assert!(
        QualificationState::empty()
            .begin(StartCommitment::for_test(524_300, 8_192), &budget)
            .is_err()
    );
    assert_eq!(budget.usage_for_test(), (4, FULL_TRANSFER_BYTES * 4, 0));

    drop(held);
    assert_eq!(budget.usage_for_test(), (0, 0, 0));
}

#[test]
fn abort_moves_pending_start_to_retirement_before_releasing_its_lease() {
    let budget = QualificationResourceBudget::new_for_test();
    let mut state = QualificationState::empty();
    let pending = state
        .begin(StartCommitment::for_test(13, 19), &budget)
        .expect("valid start reserves bytes");

    let retirement = state.abort(pending);
    assert!(!state.is_allocating());
    assert_eq!(budget.usage_for_test(), (1, 32, 0));

    drop(retirement);
    assert_eq!(budget.usage_for_test(), (0, 0, 0));
}

#[test]
fn failed_buffer_allocation_returns_the_unchanged_pending_lease_for_retirement() {
    struct FailingAllocator;

    impl QualificationAllocator for FailingAllocator {
        fn reserve(&self, _: &mut Vec<u8>, _: usize) -> Result<(), ()> {
            Err(())
        }
    }

    let budget = QualificationResourceBudget::new_for_test();
    let mut state = QualificationState::empty();
    let pending = state
        .begin(StartCommitment::for_test(13, 19), &budget)
        .expect("valid start reserves bytes");
    let Err(pending) = pending.allocate_with(&FailingAllocator) else {
        panic!("allocator failure keeps the complete owner intact");
    };

    let retirement = state.abort(pending);
    assert_eq!(budget.usage_for_test(), (1, 32, 0));
    drop(retirement);
    assert_eq!(budget.usage_for_test(), (0, 0, 0));
}

#[test]
fn receiving_buffers_move_to_deferred_retirement_before_their_lease_releases() {
    let budget = QualificationResourceBudget::new_for_test();
    let mut state = QualificationState::empty();
    let pending = state
        .begin(StartCommitment::for_test(13, 19), &budget)
        .expect("valid start reserves bytes");
    let Ok(allocated) = pending.allocate_with(&SystemQualificationAllocator) else {
        panic!("fallible system allocation is available for the bounded fixture");
    };

    assert!(
        state.commit_allocation(allocated).is_ok(),
        "live allocation token commits"
    );
    let Some(retirement) = state.retire_receiving() else {
        panic!("receiving buffers detach");
    };
    assert_eq!(budget.usage_for_test(), (1, 32, 0));

    drop(retirement);
    assert_eq!(budget.usage_for_test(), (0, 0, 0));
}

#[test]
fn paired_clock_sampling_reads_wall_and_monotonic_once_at_the_transition_boundary() {
    use std::{cell::Cell, time::Instant};

    struct FixedClock {
        wall_reads: Cell<u8>,
        monotonic_reads: Cell<u8>,
        monotonic: Instant,
    }

    impl QualificationClockSource for FixedClock {
        fn wall_unix_millis(&self) -> u64 {
            self.wall_reads.set(self.wall_reads.get() + 1);
            100
        }

        fn monotonic_now(&self) -> Instant {
            self.monotonic_reads.set(self.monotonic_reads.get() + 1);
            self.monotonic
        }
    }

    let source = FixedClock {
        wall_reads: Cell::new(0),
        monotonic_reads: Cell::new(0),
        monotonic: Instant::now(),
    };
    let clocks = LockedCredentialServiceClocks::sample_pair(&source);

    assert_eq!(clocks.wall_unix_millis(), 100);
    assert_eq!(clocks.monotonic_now(), source.monotonic);
    assert_eq!(
        (source.wall_reads.get(), source.monotonic_reads.get()),
        (1, 1)
    );
}
