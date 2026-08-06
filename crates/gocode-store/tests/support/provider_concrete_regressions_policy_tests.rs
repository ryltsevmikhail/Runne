use super::*;

#[test]
fn serialized_prohibited_and_unavailable_guards_stop_before_prepare() {
    for mode in [GuardMode::Prohibited, GuardMode::Unavailable] {
        let (_directory, dispatch, execution, request) = fixture();
        let provider = Provider::new(Response::Stream);
        let guard = Guard {
            mode,
            saw_marker: Mutex::new(false),
        };
        let coordinator = SqliteProviderDispatchCoordinator::new(
            &dispatch, &execution, &provider, &provider, &guard,
        );
        assert_eq!(
            block_on(coordinator.dispatch(request)),
            Err(ProviderAdmissionError::PolicyDenied)
        );
        assert!(*guard.saw_marker.lock().unwrap());
        assert!(provider.prepared.lock().unwrap().is_empty());
        assert_eq!(*provider.dispatched.lock().unwrap(), 0);
        assert_eq!(execution.admitted_count().unwrap(), 0);
    }
}

#[test]
fn oversized_reservations_are_rejected_before_admission_or_dispatch() {
    for oversized_output in [false, true] {
        let (_directory, dispatch, execution, mut request) = fixture();
        if oversized_output {
            request.requested_output_tokens =
                u32::try_from(gocode_provider::MAX_PROVIDER_USAGE_TOKENS + 1).unwrap();
        } else {
            request.requested_input_tokens = gocode_provider::MAX_PROVIDER_USAGE_TOKENS + 1;
        }
        let provider = Provider::new(Response::Stream);
        let guard = Guard {
            mode: GuardMode::Allowed,
            saw_marker: Mutex::new(false),
        };
        let coordinator = SqliteProviderDispatchCoordinator::new(
            &dispatch, &execution, &provider, &provider, &guard,
        );
        assert_eq!(
            block_on(coordinator.dispatch(request)),
            Err(ProviderAdmissionError::InvalidSemanticContext)
        );
        assert_eq!(*provider.dispatched.lock().unwrap(), 0);
        assert_eq!(execution.admitted_count().unwrap(), 0);
    }
}
