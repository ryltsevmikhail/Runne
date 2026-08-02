use super::*;

#[test]
fn post_dispatch_stream_persistence_failure_is_uncertain() {
    let (directory, dispatch, execution, request) = fixture();
    Connection::open(directory.path().join("provider.sqlite"))
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_stream_binding
             BEFORE UPDATE OF stream_id ON provider_dispatch_attempts
             BEGIN SELECT RAISE(ABORT, 'stream write unavailable'); END",
        )
        .unwrap();
    let provider = RecordingProvider::new(ProviderMode::Streaming);
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &dispatch,
        &execution,
        &provider,
        &provider,
        &Guard(true),
    );

    assert_eq!(
        block_on(coordinator.dispatch(request)).unwrap(),
        ProviderCoordinatorOutcome::Uncertain
    );
    assert_eq!(provider.dispatched(), 1);
}
