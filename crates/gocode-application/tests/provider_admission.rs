include!("provider_admission/support.rs");

#[test]
fn every_admission_rejection_prevents_adapter_dispatch() {
    let failures = [
        ProviderAdmissionError::CapabilityDenied,
        ProviderAdmissionError::TokenReservationMismatch,
        ProviderAdmissionError::CostReservationMismatch,
        ProviderAdmissionError::RenderDigestMismatch,
        ProviderAdmissionError::PermitMismatch,
        ProviderAdmissionError::StaleFencingToken,
    ];

    for failure in failures {
        let repository = RecordingRepository::winner();
        let admission = RecordingAdmission::rejecting(failure.clone());
        let adapter = adapter();
        let guard = AvailableGuard;
        let coordinator =
            ProviderDispatchCoordinator::new(&repository, &admission, &adapter, &guard);

        assert_eq!(block_on(coordinator.dispatch(request())), Err(failure));
        assert_eq!(adapter.dispatch_count(), 0);
        assert_eq!(*repository.uncertain_count.lock().unwrap(), 0);
    }
}

#[test]
fn claim_replay_verifies_admission_without_adapter_dispatch() {
    let repository = RecordingRepository::existing();
    let admission = RecordingAdmission::allowing();
    let adapter = adapter();
    let guard = AvailableGuard;
    let coordinator = ProviderDispatchCoordinator::new(&repository, &admission, &adapter, &guard);

    assert_eq!(
        block_on(coordinator.dispatch(request())).unwrap(),
        ProviderCoordinatorOutcome::Existing {
            state: ProviderRepositoryState::Dispatching,
        }
    );
    assert_eq!(*admission.count.lock().unwrap(), 1);
    assert_eq!(adapter.dispatch_count(), 0);
}

#[test]
fn existing_claim_rejects_unknown_authority_without_adapter_dispatch() {
    let repository = RecordingRepository::existing();
    let admission = RecordingAdmission::rejecting(ProviderAdmissionError::AuthorityDenied);
    let adapter = adapter();
    let guard = AvailableGuard;
    let coordinator = ProviderDispatchCoordinator::new(&repository, &admission, &adapter, &guard);

    assert_eq!(
        block_on(coordinator.dispatch(request())),
        Err(ProviderAdmissionError::AuthorityDenied)
    );
    assert_eq!(*admission.count.lock().unwrap(), 1);
    assert_eq!(adapter.dispatch_count(), 0);
}

#[test]
fn existing_claim_rejects_changed_authority_without_adapter_dispatch() {
    let repository = RecordingRepository::existing();
    let admission = RecordingAdmission::rejecting(ProviderAdmissionError::AuthorityConflict);
    let adapter = adapter();
    let guard = AvailableGuard;
    let coordinator = ProviderDispatchCoordinator::new(&repository, &admission, &adapter, &guard);

    assert_eq!(
        block_on(coordinator.dispatch(request())),
        Err(ProviderAdmissionError::AuthorityConflict)
    );
    assert_eq!(*admission.count.lock().unwrap(), 1);
    assert_eq!(adapter.dispatch_count(), 0);
}

#[test]
fn winner_is_admitted_once_and_dispatches_once() {
    let repository = RecordingRepository::winner();
    let admission = RecordingAdmission::allowing();
    let adapter = adapter();
    let guard = AvailableGuard;
    let coordinator = ProviderDispatchCoordinator::new(&repository, &admission, &adapter, &guard);

    assert!(matches!(
        block_on(coordinator.dispatch(request())).unwrap(),
        ProviderCoordinatorOutcome::Streaming { .. }
    ));
    assert_eq!(*admission.count.lock().unwrap(), 1);
    assert_eq!(adapter.dispatch_count(), 1);
    assert_eq!(*repository.streaming_count.lock().unwrap(), 1);
}

#[test]
fn post_claim_uncertainty_is_persisted_without_adapter_dispatch() {
    let repository = RecordingRepository::winner();
    let admission = RecordingAdmission::rejecting(ProviderAdmissionError::PostClaimUncertain);
    let adapter = adapter();
    let guard = AvailableGuard;
    let coordinator = ProviderDispatchCoordinator::new(&repository, &admission, &adapter, &guard);

    assert_eq!(
        block_on(coordinator.dispatch(request())),
        Ok(ProviderCoordinatorOutcome::Uncertain)
    );
    assert_eq!(*repository.uncertain_count.lock().unwrap(), 1);
    assert_eq!(adapter.dispatch_count(), 0);
}
