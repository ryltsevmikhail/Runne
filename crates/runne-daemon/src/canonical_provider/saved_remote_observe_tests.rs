use super::*;
use runne_provider::{
    ProviderFuture, ProviderRecoveryError, ProviderRecoveryRequest, ProviderRemoteCheck,
};
use std::sync::atomic::{AtomicUsize, Ordering};

struct RecordingAdapter {
    status_calls: AtomicUsize,
    cancel_calls: AtomicUsize,
    status_error: ProviderRecoveryError,
    cancel_error: ProviderRecoveryError,
}

impl RecordingAdapter {
    fn failing(status_error: ProviderRecoveryError, cancel_error: ProviderRecoveryError) -> Self {
        Self {
            status_calls: AtomicUsize::new(0),
            cancel_calls: AtomicUsize::new(0),
            status_error,
            cancel_error,
        }
    }
}

impl SavedRemoteRecoveryAdapter for RecordingAdapter {
    fn check_remote_status(
        &self,
        _: ProviderRecoveryRequest,
    ) -> ProviderFuture<'_, Result<ProviderRemoteCheck, ProviderRecoveryError>> {
        self.status_calls.fetch_add(1, Ordering::SeqCst);
        let error = self.status_error;
        Box::pin(async move { Err(error) })
    }

    fn cancel_remote(
        &self,
        _: ProviderRecoveryRequest,
    ) -> ProviderFuture<'_, Result<ProviderRemoteCheck, ProviderRecoveryError>> {
        self.cancel_calls.fetch_add(1, Ordering::SeqCst);
        let error = self.cancel_error;
        Box::pin(async move { Err(error) })
    }
}

fn candidate(
    status_check_supported: bool,
    remote_cancel_requested: bool,
) -> SavedRemoteRecoveryCandidate {
    SavedRemoteRecoveryCandidate {
        dispatch_attempt_id: runne_provider::DispatchAttemptId::from_bytes([3; 16]),
        taskrun_id: runne_domain::id::TaskRunId::from_bytes([1; 16]),
        task_attempt_id: runne_domain::id::AttemptId::from_bytes([2; 16]),
        status_check_supported,
        accepted_cancel_requested: remote_cancel_requested,
        remote_cancel_requested,
    }
}

fn request() -> ProviderRecoveryRequest {
    let binding = runne_provider::ProviderRecoveryBinding::new(
        runne_domain::id::TaskRunId::from_bytes([1; 16]),
        runne_domain::id::AttemptId::from_bytes([2; 16]),
        runne_provider::DispatchAttemptId::from_bytes([3; 16]),
        [4; 32],
    )
    .unwrap();
    ProviderRecoveryRequest::new(
        binding,
        runne_provider::RemoteResponseId::new("saved-response").unwrap(),
    )
}

#[tokio::test(flavor = "current_thread")]
async fn ordinary_recovery_uses_status_only_even_when_adapter_supports_cancel() {
    let adapter = RecordingAdapter::failing(
        ProviderRecoveryError::Unavailable,
        ProviderRecoveryError::Unavailable,
    );
    let outcome = check_saved_response(&adapter, &candidate(true, false), request()).await;
    assert!(matches!(
        outcome,
        Err(SavedRemoteObservationOutcome::Unknown)
    ));
    assert_eq!(adapter.status_calls.load(Ordering::SeqCst), 1);
    assert_eq!(adapter.cancel_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn no_status_or_durable_cancel_intent_makes_no_remote_call() {
    let adapter = RecordingAdapter::failing(
        ProviderRecoveryError::Unavailable,
        ProviderRecoveryError::Unavailable,
    );
    let outcome = check_saved_response(&adapter, &candidate(false, false), request()).await;
    assert!(matches!(
        outcome,
        Err(SavedRemoteObservationOutcome::Unsupported)
    ));
    assert_eq!(adapter.status_calls.load(Ordering::SeqCst), 0);
    assert_eq!(adapter.cancel_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn durable_cancel_intent_is_independent_of_status_capability() {
    let adapter = RecordingAdapter::failing(
        ProviderRecoveryError::Unavailable,
        ProviderRecoveryError::Unsupported,
    );
    let outcome = check_saved_response(&adapter, &candidate(false, true), request()).await;
    assert!(matches!(
        outcome,
        Err(SavedRemoteObservationOutcome::Unsupported)
    ));
    assert_eq!(adapter.cancel_calls.load(Ordering::SeqCst), 1);
    assert_eq!(adapter.status_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn failed_cancel_falls_back_to_independently_supported_status() {
    let adapter = RecordingAdapter::failing(
        ProviderRecoveryError::Unavailable,
        ProviderRecoveryError::Unavailable,
    );
    let outcome = check_saved_response(&adapter, &candidate(true, true), request()).await;
    assert!(matches!(
        outcome,
        Err(SavedRemoteObservationOutcome::Unknown)
    ));
    assert_eq!(adapter.cancel_calls.load(Ordering::SeqCst), 1);
    assert_eq!(adapter.status_calls.load(Ordering::SeqCst), 1);
}
