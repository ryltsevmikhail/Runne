use runne_application::migration::fence::FenceError;
use runne_application::migration::types::{FencingToken, RoutingGeneration};
use runne_platform::fence::FenceRegistry;

#[test]
fn stale_token_cannot_dispatch_or_confirm() {
    let registry = FenceRegistry::new(routing_generation(8), token(8));

    assert_eq!(
        registry.authorize_dispatch(routing_generation(7), token(7), || ()),
        Err(FenceError::StaleFencingToken {
            current_generation: routing_generation(8),
            attempted_generation: routing_generation(7),
        })
    );
    assert_eq!(
        registry.authorize_confirmation(routing_generation(7), token(7), || ()),
        Err(FenceError::StaleFencingToken {
            current_generation: routing_generation(8),
            attempted_generation: routing_generation(7),
        })
    );
    assert_eq!(registry.dispatched_count(), 0);
    assert_eq!(registry.confirmed_count(), 0);
}

#[test]
fn generation_and_token_must_both_match() {
    let registry = FenceRegistry::new(routing_generation(8), token(8));

    assert_eq!(
        registry.authorize_dispatch(routing_generation(8), token(7), || ()),
        Err(FenceError::TokenMismatch)
    );
    registry
        .authorize_dispatch(routing_generation(8), token(8), || ())
        .unwrap();
    registry
        .authorize_confirmation(routing_generation(8), token(8), || ())
        .unwrap();

    assert_eq!(registry.dispatched_count(), 1);
    assert_eq!(registry.confirmed_count(), 1);
}

#[test]
fn fence_updates_are_monotonic_and_same_generation_is_immutable() {
    let registry = FenceRegistry::new(routing_generation(8), token(8));

    assert_eq!(
        registry.activate(routing_generation(7), token(7)),
        Err(FenceError::GenerationRegression {
            current_generation: routing_generation(8),
            attempted_generation: routing_generation(7),
        })
    );
    assert_eq!(
        registry.activate(routing_generation(8), token(9)),
        Err(FenceError::ConflictingToken)
    );
    registry.activate(routing_generation(9), token(9)).unwrap();
    assert_eq!(
        registry.authorize_dispatch(routing_generation(8), token(8), || ()),
        Err(FenceError::StaleFencingToken {
            current_generation: routing_generation(9),
            attempted_generation: routing_generation(8),
        })
    );
}

#[test]
fn fence_activation_waits_for_an_authorized_effect_boundary() {
    let registry = Arc::new(FenceRegistry::new(routing_generation(8), token(8)));
    let (effect_entered_tx, effect_entered_rx) = mpsc::channel();
    let (release_effect_tx, release_effect_rx) = mpsc::channel();
    let dispatch_registry = Arc::clone(&registry);
    let dispatch = std::thread::spawn(move || {
        dispatch_registry
            .authorize_dispatch(routing_generation(8), token(8), || {
                effect_entered_tx.send(()).unwrap();
                release_effect_rx.recv().unwrap();
            })
            .unwrap();
    });
    effect_entered_rx.recv().unwrap();

    let (activation_started_tx, activation_started_rx) = mpsc::channel();
    let (activation_done_tx, activation_done_rx) = mpsc::channel();
    let activation_registry = Arc::clone(&registry);
    let activation = std::thread::spawn(move || {
        activation_started_tx.send(()).unwrap();
        let result = activation_registry.activate(routing_generation(9), token(9));
        activation_done_tx.send(result).unwrap();
    });
    activation_started_rx.recv().unwrap();

    assert_eq!(
        activation_done_rx.recv_timeout(Duration::from_millis(20)),
        Err(mpsc::RecvTimeoutError::Timeout)
    );
    release_effect_tx.send(()).unwrap();
    dispatch.join().unwrap();
    assert_eq!(activation_done_rx.recv().unwrap(), Ok(()));
    activation.join().unwrap();
}

fn routing_generation(value: u64) -> RoutingGeneration {
    RoutingGeneration::new(value).unwrap()
}

fn token(value: u8) -> FencingToken {
    FencingToken::new([value; 32]).unwrap()
}
use std::{
    sync::{Arc, mpsc},
    time::Duration,
};
