use std::sync::Arc;

use gocode_application::migration::{
    fence::FenceError,
    types::{FencingToken, RoutingGeneration},
};
use gocode_platform::fence::FenceRegistry;
use gocode_runtime::migration_fence::MigrationFenceGuard;

#[test]
fn ingress_validation_is_rechecked_before_worker_dispatch() {
    let registry = Arc::new(FenceRegistry::new(routing_generation(8), token(8)));
    let guard = MigrationFenceGuard::new(Arc::clone(&registry));
    let admitted = guard
        .validate_ingress(routing_generation(8), token(8))
        .unwrap();

    registry.activate(routing_generation(9), token(9)).unwrap();

    assert_eq!(
        guard.validate_worker_dispatch(&admitted),
        Err(FenceError::StaleFencingToken {
            current_generation: routing_generation(9),
            attempted_generation: routing_generation(8),
        })
    );
    assert_eq!(registry.dispatched_count(), 0);
}

#[test]
fn matching_fence_passes_ingress_worker_and_confirmation_validation() {
    let registry = Arc::new(FenceRegistry::new(routing_generation(8), token(8)));
    let guard = MigrationFenceGuard::new(Arc::clone(&registry));
    let admitted = guard
        .validate_ingress(routing_generation(8), token(8))
        .unwrap();

    guard.validate_worker_dispatch(&admitted).unwrap();
    guard.validate_confirmation(&admitted).unwrap();

    assert_eq!(registry.dispatched_count(), 0);
    assert_eq!(registry.confirmed_count(), 0);
}

fn routing_generation(value: u64) -> RoutingGeneration {
    RoutingGeneration::new(value).unwrap()
}

fn token(value: u8) -> FencingToken {
    FencingToken::new([value; 32]).unwrap()
}
