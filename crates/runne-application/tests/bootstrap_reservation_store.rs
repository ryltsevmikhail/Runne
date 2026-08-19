use std::sync::{Arc, atomic::Ordering};
use std::time::Duration;

use runne_application::local_session::{
    BOOTSTRAP_FINAL_ENDPOINT_V3, BOOTSTRAP_HTTP_METHOD_V3, BOOTSTRAP_KEY_VERSION_V3,
    BOOTSTRAP_PREALLOCATION_ENDPOINT_V3, BootstrapClock, BootstrapPreallocationProof,
    BootstrapProof, LocalSessionError, LocalSessionService,
};

#[path = "bootstrap_reservation_store/support.rs"]
mod support;
use support::*;

#[test]
fn unknown_key_version_has_no_reservation() {
    let store = Arc::new(RecordingStore::default());
    let mut service = LocalSessionService::with_reservation_store(
        binding(7),
        LAUNCH_AUTHORITY_ID,
        EXECUTABLE_SHA256,
        SECRET,
        store.clone(),
    );
    let proof = BootstrapPreallocationProof {
        key_version: 99,
        client_nonce: CLIENT_NONCE,
        not_before_rfc3339_utc_microseconds: NOT_BEFORE.to_owned(),
        expiry_rfc3339_utc_microseconds: EXPIRY.to_owned(),
        proof: BootstrapProof::new([0; 32]),
    };

    assert!(matches!(
        service.preallocate(proof, now()),
        Err(LocalSessionError::Unauthorized),
    ));
    assert_eq!(store.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn replay_returns_same_challenge_without_amplification() {
    let store = Arc::new(RecordingStore::default());
    let binding = binding(7);
    let mut service = LocalSessionService::with_reservation_store(
        binding.clone(),
        LAUNCH_AUTHORITY_ID,
        EXECUTABLE_SHA256,
        SECRET,
        store.clone(),
    );
    let proof = preallocation_proof(&binding);

    let first = service.preallocate(proof.clone(), now()).unwrap();
    let replay = service.preallocate(proof, now()).unwrap();

    assert!(first == replay);
    assert_eq!(store.allocations.load(Ordering::SeqCst), 1);
}

#[test]
fn cross_launch_endpoint_method_and_stale_proof_reject() {
    let store = Arc::new(RecordingStore::default());
    let original = binding(7);
    let mut service = LocalSessionService::with_reservation_store(
        original.clone(),
        LAUNCH_AUTHORITY_ID,
        EXECUTABLE_SHA256,
        SECRET,
        store.clone(),
    );
    let timed_proof = preallocation_proof(&original);
    assert!(matches!(
        service.preallocate(
            timed_proof.clone(),
            BootstrapClock::new(NOT_BEFORE_MICROS - 1, Duration::ZERO),
        ),
        Err(LocalSessionError::Unauthorized),
    ));
    assert!(matches!(
        service.preallocate(
            timed_proof,
            BootstrapClock::new(EXPIRY_MICROS, Duration::ZERO),
        ),
        Err(LocalSessionError::Unauthorized),
    ));
    let mut invalid_mac = preallocation_proof(&original);
    invalid_mac.proof = BootstrapProof::new([0; 32]);
    assert!(matches!(
        service.preallocate(invalid_mac, now()),
        Err(LocalSessionError::Unauthorized),
    ));
    assert_eq!(store.calls.load(Ordering::SeqCst), 0);
    let challenge = service
        .preallocate(preallocation_proof(&original), now())
        .unwrap();
    let wrong_endpoint = proof_for(
        &original,
        BOOTSTRAP_PREALLOCATION_ENDPOINT_V3,
        BOOTSTRAP_HTTP_METHOD_V3,
        Some(challenge.server_nonce),
    );
    assert!(matches!(
        service.consume_final(challenge.id, wrong_endpoint, [10; 32], now()),
        Err(LocalSessionError::Unauthorized),
    ));
    let wrong_method = proof_for(
        &original,
        BOOTSTRAP_FINAL_ENDPOINT_V3,
        b"GET",
        Some(challenge.server_nonce),
    );
    assert!(matches!(
        service.consume_final(challenge.id, wrong_method, [10; 32], now()),
        Err(LocalSessionError::Unauthorized),
    ));
    let mut next_launch = LocalSessionService::with_reservation_store(
        original.clone(),
        [0x0f; 16],
        EXECUTABLE_SHA256,
        SECRET,
        store.clone(),
    );
    let stale = final_proof(&original, challenge.server_nonce);
    assert!(matches!(
        next_launch.consume_final(challenge.id, stale, [10; 32], now()),
        Err(LocalSessionError::Unauthorized),
    ));

    let authenticated = service
        .consume_final(
            challenge.id,
            final_proof(&original, challenge.server_nonce),
            [10; 32],
            now(),
        )
        .unwrap();
    assert_eq!(authenticated.binding, original);
    assert!(matches!(
        service.consume_final(
            challenge.id,
            final_proof(&authenticated.binding, challenge.server_nonce),
            [11; 32],
            now(),
        ),
        Err(LocalSessionError::Unauthorized),
    ));
}

fn now() -> BootstrapClock {
    BootstrapClock::new(NOW_MICROS, Duration::ZERO)
}

fn preallocation_proof(binding: &runne_api::RuntimeSessionBinding) -> BootstrapPreallocationProof {
    BootstrapPreallocationProof {
        key_version: BOOTSTRAP_KEY_VERSION_V3,
        client_nonce: CLIENT_NONCE,
        not_before_rfc3339_utc_microseconds: NOT_BEFORE.to_owned(),
        expiry_rfc3339_utc_microseconds: EXPIRY.to_owned(),
        proof: proof_for(
            binding,
            BOOTSTRAP_PREALLOCATION_ENDPOINT_V3,
            BOOTSTRAP_HTTP_METHOD_V3,
            None,
        ),
    }
}

fn final_proof(
    binding: &runne_api::RuntimeSessionBinding,
    server_nonce: [u8; 32],
) -> BootstrapProof {
    proof_for(
        binding,
        BOOTSTRAP_FINAL_ENDPOINT_V3,
        BOOTSTRAP_HTTP_METHOD_V3,
        Some(server_nonce),
    )
}
