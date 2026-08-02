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
