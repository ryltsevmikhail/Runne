//! Startup self-healing for uncertain dispatches that provably never delivered.
use runne_provider::ProviderPreEffectRejection;
use runne_store::provider::SqliteProviderDispatchStore;
use std::time::{SystemTime, UNIX_EPOCH};

const CANDIDATE_LIMIT: usize = 64;

/// Closes attempts whose delivery window expired without one write-ahead record.
///
/// The settlement is proof-gated inside the store; an attempt whose delivery
/// cannot be disproved stays uncertain and untouched.
pub(super) fn settle_uncertain_without_delivery(store: &SqliteProviderDispatchStore) {
    let Ok(elapsed) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return;
    };
    let now = elapsed.as_secs();
    let Ok(candidates) = store.uncertain_without_delivery_candidates(CANDIDATE_LIMIT, now) else {
        return;
    };
    for attempt in candidates {
        let _ = store.settle_uncertain_without_delivery(
            attempt,
            ProviderPreEffectRejection::AdapterRejected,
            now,
        );
    }
}
