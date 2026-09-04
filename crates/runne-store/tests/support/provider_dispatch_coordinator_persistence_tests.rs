use super::*;

#[test]
fn post_dispatch_stream_persistence_failure_is_uncertain() {
    let (database, dispatch, execution, credential, launch, request) = fixture();
    database
        .connection()
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
        runne_store::provider::CredentialDispatchAuthority::new(&credential, &launch),
        &provider,
        &provider,
        &Guard(true),
    );

    assert_eq!(
        block_on(coordinator.dispatch(request)).unwrap(),
        ProviderCoordinatorOutcome::Uncertain
    );
    assert_eq!(provider.dispatched(), 1);
    assert_eq!(
        *provider.cancelled.lock().unwrap(),
        vec![ProviderStreamId::from_bytes([12; 16])]
    );
}
