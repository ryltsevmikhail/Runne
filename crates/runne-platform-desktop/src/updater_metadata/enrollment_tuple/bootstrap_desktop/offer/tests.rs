use std::time::{Duration, Instant};

use runne_api::{DesktopOffer, RunBinding};

use super::{validate_offer, validate_offer_deadline};

fn binding(manifest: [u8; 32]) -> RunBinding {
    RunBinding::new(
        "run-42", [1; 20], [2; 32], [3; 32], [4; 32], manifest, [6; 32],
    )
    .unwrap()
}

fn offer(challenge: [u8; 32], expires_at: u64, manifest: [u8; 32]) -> DesktopOffer {
    DesktopOffer::new(
        challenge,
        [7; 32],
        binding(manifest),
        expires_at,
        expires_at + 1,
    )
    .unwrap()
}

#[test]
fn rejects_wrong_challenge_and_expired_offer() {
    let cap = Instant::now() + Duration::from_secs(10);
    assert!(validate_offer([9; 32], &offer([8; 32], 100, [5; 32]), 99, cap).is_none());
    assert!(validate_offer_deadline(&offer([8; 32], 100, [5; 32]), 100, cap).is_none());
}

#[test]
fn binding_regression_distinguishes_full_manifest_binding() {
    let expected = binding([5; 32]);
    let changed = offer([8; 32], 100, [9; 32]);
    assert_ne!(
        expected.manifest_sha256(),
        changed.binding().manifest_sha256(),
    );
}

#[test]
fn deadline_revalidation_only_tightens_the_cap() {
    let offer = offer([8; 32], 100, [5; 32]);
    let cap = Instant::now() + Duration::from_secs(30);
    let narrowed = validate_offer_deadline(&offer, 99, cap).unwrap();
    let after_clock_rollback = validate_offer_deadline(&offer, 90, narrowed).unwrap();
    assert_eq!(after_clock_rollback, narrowed);
}
