//! Resource limits (Plan Task 12 Step 1): deterministic quotes,
//! overflow-safe arithmetic, zero money, missing-limit refusals, the
//! reservation ledger's fence/stale/capacity rules and byte-identical
//! usage settlement.

use runne_provider_local::resource_manager::{Capacity, ReservationError, ReservationLedger};
use runne_provider_local::resource_quote::{EstimateInputs, ResourceError, quote};
use runne_provider_local::settlement::{
    SettlementDisposition, SettlementError, SettlementLedger, UsageEvidence,
};
use std::time::{Duration, Instant};

fn inputs() -> EstimateInputs {
    EstimateInputs {
        artifact_bytes: 4 * 1024 * 1024 * 1024, // 4 GiB
        context_max_tokens: 4096,
        bytes_per_token: 2048,
        prompt_tokens: 128,
        max_output_tokens: 512,
        active_time_budget_ms: 60_000,
    }
}

#[test]
fn quote_is_finite_with_zero_money() {
    let q = quote(&inputs()).expect("quote");
    assert_eq!(q.prompt_tokens, 128);
    assert_eq!(q.output_tokens, 512);
    assert_eq!(q.prompt_tokens + q.output_tokens, q.context_tokens);
    assert!(q.ram_bytes >= 1024 * 1024 * 1024, "headroom floor");
    assert_eq!(q.accelerator_bytes, 0, "CPU profile");
    assert_eq!(q.price_micro_units, 0, "zero money");
}

#[test]
fn overflow_and_missing_limits_refuse() {
    let mut i = inputs();
    i.artifact_bytes = u64::MAX;
    assert!(matches!(quote(&i), Err(ResourceError::Overflow)));
    let mut i = inputs();
    i.bytes_per_token = 0;
    assert!(matches!(quote(&i), Err(ResourceError::MissingLimits(_))));
    let mut i = inputs();
    i.active_time_budget_ms = 0;
    assert!(matches!(quote(&i), Err(ResourceError::MissingLimits(_))));
}

#[test]
fn context_and_time_violations_refuse() {
    let mut i = inputs();
    i.prompt_tokens = 5000;
    i.max_output_tokens = 1;
    assert!(matches!(quote(&i), Err(ResourceError::InsufficientContext)));
    let mut i = inputs();
    i.max_output_tokens = 10_000_000;
    i.active_time_budget_ms = 1000;
    assert!(matches!(quote(&i), Err(ResourceError::InsufficientTime)));
}

#[test]
fn stale_reservation_is_refused_after_ttl() {
    let now = Instant::now();
    let mut ledger = ReservationLedger::new(Capacity {
        total_ram_bytes: u64::MAX,
        reservation_ttl: Duration::from_millis(50),
    });
    let q = quote(&inputs()).expect("quote");
    let fence = ledger
        .reserve([1; 16], "local:m1", &q, now)
        .expect("reserve");
    let later = now + Duration::from_millis(200);
    let err = ledger.commit(&[1; 16], fence, later).expect_err("stale");
    assert_eq!(err, ReservationError::StaleReservation);
}

#[test]
fn fence_mismatch_refuses() {
    let now = Instant::now();
    let mut ledger = ReservationLedger::new(Capacity {
        total_ram_bytes: u64::MAX,
        reservation_ttl: Duration::from_secs(60),
    });
    let q = quote(&inputs()).expect("quote");
    let _fence = ledger
        .reserve([1; 16], "local:m1", &q, now)
        .expect("reserve");
    let err = ledger
        .commit(
            &[1; 16],
            runne_provider_local::resource_manager::Fence(999),
            now,
        )
        .expect_err("fence");
    assert_eq!(err, ReservationError::FenceMismatch);
}

#[test]
fn capacity_exhaustion_and_duplicate_attempt_refuse() {
    let now = Instant::now();
    let mut ledger = ReservationLedger::new(Capacity {
        total_ram_bytes: 2 * 1024 * 1024 * 1024,
        reservation_ttl: Duration::from_secs(60),
    });
    let q = quote(&inputs()).expect("quote needs > 2 GiB");
    let err = ledger
        .reserve([1; 16], "local:m1", &q, now)
        .expect_err("capacity");
    assert_eq!(err, ReservationError::CapacityExhausted);

    let mut big = ReservationLedger::new(Capacity {
        total_ram_bytes: u64::MAX,
        reservation_ttl: Duration::from_secs(60),
    });
    big.reserve([1; 16], "local:m1", &q, now).expect("r1");
    let err = big
        .reserve([1; 16], "local:m1", &q, now)
        .expect_err("duplicate");
    assert_eq!(err, ReservationError::DuplicateAttempt);
}

#[test]
fn settlement_is_byte_identical_discipline() {
    let mut ledger = SettlementLedger::default();
    let evidence = UsageEvidence {
        prompt_tokens: 128,
        output_tokens: 512,
        reasoning_output_tokens: 0,
        active_time_ms: 10_240,
        peak_bytes: 4_295_000_000,
    };
    assert_eq!(
        ledger.settle([1; 16], evidence).expect("first"),
        SettlementDisposition::Settled
    );
    assert_eq!(
        ledger.settle([1; 16], evidence).expect("repeat"),
        SettlementDisposition::AlreadySettled
    );
    let conflicting = UsageEvidence {
        output_tokens: 513,
        ..evidence
    };
    assert!(matches!(
        ledger.settle([1; 16], conflicting),
        Err(SettlementError::ConflictFrozen)
    ));
    assert!(ledger.is_frozen(&[1; 16]));
}
