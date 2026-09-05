use std::sync::atomic::{AtomicUsize, Ordering};

use runne_provider::{
    ProviderCredentialEnrollmentStore, ProviderCredentialVersionStore, RevokeCredentialVersion,
};

use super::*;

#[test]
fn prohibited_content_stops_prepare_admission_and_dispatch() {
    let (_database, dispatch, execution, credential, launch, request) = fixture();
    let provider = RecordingProvider::new(ProviderMode::Streaming);
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &dispatch,
        &execution,
        runne_store::provider::CredentialDispatchAuthority::new(&credential, &launch),
        &provider,
        &provider,
        &Guard(false),
    );
    assert!(matches!(
        block_on(coordinator.dispatch(request)),
        Err(runne_application::provider::ProviderAdmissionError::PolicyDenied)
    ));
    assert_eq!(*provider.prepared.lock().unwrap(), 0);
    assert_eq!(provider.dispatched(), 0);
    assert_eq!(execution.admitted_count().unwrap(), 0);
}

#[test]
fn sqlite_admission_dispatches_once_and_exact_replay_never_redispaches() {
    let (_database, dispatch, execution, credential, launch, request) = fixture();
    let provider = RecordingProvider::new(ProviderMode::Streaming);
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &dispatch,
        &execution,
        runne_store::provider::CredentialDispatchAuthority::new(&credential, &launch),
        &provider,
        &provider,
        &Guard(true),
    );
    assert!(matches!(
        block_on(coordinator.dispatch(request.clone())),
        Ok(ProviderCoordinatorOutcome::Streaming { .. })
    ));
    assert!(matches!(
        block_on(coordinator.dispatch(request)),
        Ok(ProviderCoordinatorOutcome::Existing { .. })
    ));
    assert_eq!(provider.dispatched(), 1);
}

struct RevokingEffect<'a> {
    lifecycle: &'a SqliteProviderCredentialLifecycleStore,
    sends: AtomicUsize,
}

impl ProviderEffectPort for RevokingEffect<'_> {
    fn stage_effect(
        &self,
        request: DispatchRequest,
        credential: CredentialDispatchBinding,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        self.lifecycle
            .revoke_and_fence(
                RevokeCredentialVersion::new(credential.version_ref().clone(), 1).unwrap(),
            )
            .unwrap();
        Box::pin(async move { Ok(Box::new(Ready(request)) as Box<dyn ProviderReadyEffect>) })
    }

    fn dispatch_effect(
        &self,
        _: Box<dyn ProviderReadyEffect>,
        _: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(ProviderStreamId::from_bytes([12; 16])) })
    }
}

#[test]
fn revocation_during_staging_cannot_race_through_effect_start() {
    let (database, dispatch, execution, credential, launch, request) = fixture();
    let provider = RecordingProvider::new(ProviderMode::Streaming);
    let effect = RevokingEffect {
        lifecycle: &credential,
        sends: AtomicUsize::new(0),
    };
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &dispatch,
        &execution,
        runne_store::provider::CredentialDispatchAuthority::new(&credential, &launch),
        &provider,
        &effect,
        &Guard(true),
    );

    assert!(matches!(
        block_on(coordinator.dispatch(request)),
        Ok(ProviderCoordinatorOutcome::RejectedBeforeEffect { .. })
    ));
    assert_eq!(effect.sends.load(Ordering::SeqCst), 0);
    let bindings: i64 = database
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM provider_credential_effect_bindings",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(bindings, 0);
}

struct CompletionRevokingEffect<'a> {
    lifecycle: &'a SqliteProviderCredentialLifecycleStore,
    sends: AtomicUsize,
}

impl ProviderEffectPort for CompletionRevokingEffect<'_> {
    fn stage_effect(
        &self,
        request: DispatchRequest,
        _: CredentialDispatchBinding,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        Box::pin(async move { Ok(Box::new(Ready(request)) as Box<dyn ProviderReadyEffect>) })
    }

    fn dispatch_effect(
        &self,
        _: Box<dyn ProviderReadyEffect>,
        _: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async move {
            self.sends.fetch_add(1, Ordering::SeqCst);
            self.lifecycle
                .revoke_and_fence(
                    RevokeCredentialVersion::new(active_version(self.lifecycle), 1).unwrap(),
                )
                .unwrap();
            Ok(ProviderStreamId::from_bytes([12; 16]))
        })
    }
}

fn active_version(
    lifecycle: &SqliteProviderCredentialLifecycleStore,
) -> runne_provider::CredentialVersionRef {
    ProviderCredentialEnrollmentStore::lifecycle_snapshot(
        lifecycle,
        &ProviderId::new("fixture").unwrap(),
    )
    .unwrap()
    .active_version()
    .unwrap()
    .clone()
}

#[test]
fn revoke_winning_at_effect_completion_cancels_stream_and_exact_replay_never_retries() {
    let (_database, dispatch, execution, credential, launch, request) = fixture();
    let provider = RecordingProvider::new(ProviderMode::Streaming);
    let effect = CompletionRevokingEffect {
        lifecycle: &credential,
        sends: AtomicUsize::new(0),
    };
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &dispatch,
        &execution,
        runne_store::provider::CredentialDispatchAuthority::new(&credential, &launch),
        &provider,
        &effect,
        &Guard(true),
    );

    assert_eq!(
        block_on(coordinator.dispatch(request.clone())).unwrap(),
        ProviderCoordinatorOutcome::Uncertain
    );
    assert_eq!(effect.sends.load(Ordering::SeqCst), 1);
    assert_eq!(
        *provider.cancelled.lock().unwrap(),
        vec![ProviderStreamId::from_bytes([12; 16])]
    );
    assert!(matches!(
        block_on(coordinator.dispatch(request)),
        Ok(ProviderCoordinatorOutcome::Existing { .. })
    ));
    assert_eq!(effect.sends.load(Ordering::SeqCst), 1);
}
