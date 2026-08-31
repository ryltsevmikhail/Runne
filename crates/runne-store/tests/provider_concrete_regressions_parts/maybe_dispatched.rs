#[test]
fn maybe_dispatched_is_durable_uncertain_and_never_retries() {
    let (_directory, dispatch, execution, credential, launch, request) = fixture();
    let provider = Provider::new(Response::MaybeDispatched);
    let guard = Guard { mode: GuardMode::Allowed, saw_marker: Mutex::new(false) };
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &dispatch,
        &execution,
        runne_store::provider::CredentialDispatchAuthority::new(&credential, &launch),
        &provider,
        &provider,
        &guard,
    );
    assert_eq!(
        block_on(coordinator.dispatch(request.clone())).unwrap(),
        ProviderCoordinatorOutcome::Uncertain
    );
    assert!(matches!(
        block_on(coordinator.dispatch(request)),
        Ok(ProviderCoordinatorOutcome::Existing {
            state: runne_provider::ProviderRepositoryState::Uncertain
        })
    ));
    assert_eq!(*provider.dispatched.lock().unwrap(), 1);
}
