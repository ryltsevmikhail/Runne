//! Idle unload and the selected-model removal saga (Plan Task 12):
//! unload happens only with zero active attempts and records terminal
//! cleanup evidence; the selection authority never infers defaults,
//! fences removal-in-flight digests and consumes removal permits
//! exactly once.

use runne_provider_local::resource_manager::{Capacity, ReservationError, ReservationLedger};
use runne_provider_local::selected_model::{
    ModelRemovalPermit, RemovalStage, SelectedModelStore, Selection, SelectionError,
};
use std::time::{Duration, Instant};

fn one_gib() -> runne_provider_local::resource_quote::LocalResourceQuote {
    let inputs = runne_provider_local::resource_quote::EstimateInputs {
        artifact_bytes: 256 * 1024 * 1024,
        context_max_tokens: 1024,
        bytes_per_token: 512,
        prompt_tokens: 32,
        max_output_tokens: 64,
        active_time_budget_ms: 60_000,
    };
    runne_provider_local::resource_quote::quote(&inputs).expect("quote")
}

#[test]
fn idle_unload_only_after_zero_reservations() {
    let now = Instant::now();
    let mut ledger = ReservationLedger::new(Capacity {
        total_ram_bytes: u64::MAX,
        reservation_ttl: Duration::from_secs(60),
    });
    let q = one_gib();
    let fence = ledger.reserve([1; 16], "local:m1", &q, now).expect("r");
    ledger.commit(&[1; 16], fence, now).expect("commit");
    assert_eq!(ledger.loaded_model(), Some("local:m1"));
    // Active attempt holds the model: unload precondition unmet — a
    // release with a wrong fence is refused and changes nothing.
    assert_eq!(
        ledger.release(&[1; 16], runne_provider_local::resource_manager::Fence(999)),
        Err(ReservationError::FenceMismatch)
    );
    assert_eq!(ledger.loaded_model(), Some("local:m1"));
    // Proven terminal release (exact fence) empties the ledger; the
    // model slot frees only here — the idle unload evidence.
    ledger.release(&[1; 16], fence).expect("release");
    assert_eq!(ledger.loaded_model(), None);
}

#[test]
fn sweep_drops_only_stale_uncommitted() {
    let now = Instant::now();
    let mut ledger = ReservationLedger::new(Capacity {
        total_ram_bytes: u64::MAX,
        reservation_ttl: Duration::from_millis(100),
    });
    let q = one_gib();
    ledger.reserve([1; 16], "local:m1", &q, now).expect("r1");
    let later = now + Duration::from_millis(500);
    assert_eq!(ledger.sweep_stale(later), 1);
    assert!(ledger.reservations_empty());
}

// --- selection authority ---

fn selection(digest: &str) -> Selection {
    Selection {
        provider_id: "local".into(),
        model_id: "m1".into(),
        manifest_digest: digest.into(),
        backend_profile: "llama-cpp-cpu-macos-arm64-v1".into(),
    }
}

#[test]
fn selection_is_explicit_and_monotonic() {
    let mut store = SelectedModelStore::new();
    assert!(store.resolve().is_none(), "never an inferred default");
    let g1 = store.select(selection("d1"), None).expect("select");
    assert_eq!(g1.0, 1);
    let g2 = store.select(selection("d2"), None).expect("reselect");
    assert_eq!(g2.0, 2, "monotonic generation");
    assert_eq!(store.resolve().expect("some").1, g2);
}

#[test]
fn removal_saga_fences_consumes_and_recovers() {
    let mut store = SelectedModelStore::new();
    store.select(selection("d1"), None).expect("select d1");
    // In-use removal refuses.
    assert_eq!(store.begin_removal("d1"), Err(SelectionError::InUse));
    store.select(selection("d2"), None).expect("switch");
    store.set_loaded(Some("d1"));
    // Loaded model removal refuses too.
    assert_eq!(store.begin_removal("d1"), Err(SelectionError::InUse));
    store.set_loaded(None);

    let permit = store.begin_removal("d1").expect("permit");
    // Fenced for NEW selection while pending.
    assert_eq!(
        store.select(selection("d1"), None),
        Err(SelectionError::RemovalFenced)
    );
    // Crash before completion: recovery with the exact permit rolls
    // the saga FORWARD to completed.
    assert!(store.recover(Some(permit.clone())));
    // The permit is consumed exactly once.
    assert_eq!(
        store.complete_removal(permit.clone()),
        Err(SelectionError::PermitInvalid)
    );

    // Crash WITHOUT a surviving permit: availability is restored.
    let permit2 = store.begin_removal("d1").expect("second saga");
    assert!(!store.recover(None));
    assert_eq!(
        store.complete_removal(permit2),
        Err(SelectionError::PermitInvalid)
    );
    // After restore, the digest is selectable again.
    assert!(store.select(selection("d1"), None).is_ok());
}

#[test]
fn permit_is_single_use_by_digest() {
    let mut store = SelectedModelStore::new();
    let p1 = store.begin_removal("dA").expect("permit A");
    // Another removal while pending is refused (linearized).
    assert_eq!(
        store.begin_removal("dB"),
        Err(SelectionError::RemovalInFlight)
    );
    assert_eq!(
        p1,
        ModelRemovalPermit {
            manifest_digest: "dA".into(),
            permit_id: 1
        }
    );
    store.complete_removal(p1).expect("completed");
    assert!(matches!(store.removal_stage(), RemovalStage::Completed));
}
