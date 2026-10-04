use super::*;
use std::sync::atomic::AtomicI64;

// The transport double completes only after a real durable Revoke. It records
// the exact cancellation contract; SQLite admission/publication are not mocked.
struct CompletedAfterRevoke {
    path: std::path::PathBuf,
    cancelled: Mutex<Vec<ProviderStreamId>>,
    stall_cancel: bool,
    finish_at: Option<i64>,
    now: Arc<AtomicI64>,
}

impl ProviderPort for CompletedAfterRevoke {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call(call)
    }
    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        version: runne_provider::ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call_for_digest_version(call, version)
    }
    fn dispatch(
        &self,
        _: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async { panic!("legacy dispatch is forbidden") })
    }
    fn next<'a>(
        &'a self,
        _: &'a ProviderStreamId,
        _: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        Box::pin(async { panic!("unpublished stream must not be consumed") })
    }
    fn cancel(
        &self,
        request: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        Box::pin(async move {
            self.cancelled.lock().unwrap().push(request.stream_id());
            if self.stall_cancel {
                return std::future::pending().await;
            }
            Ok(CancelDisposition::Requested)
        })
    }
    fn reconcile(
        &self,
        _: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { panic!("no implicit reconciliation") })
    }
}

impl ProviderEffectPort for CompletedAfterRevoke {
    fn stage_effect(
        &self,
        _: DispatchRequest,
        _: CredentialDispatchBinding,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        Box::pin(async { Ok(Box::new(Ready) as Box<dyn ProviderReadyEffect>) })
    }
    fn dispatch_effect(
        &self,
        _: Box<dyn ProviderReadyEffect>,
        mut receipt: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async move {
            receipt
                .take_final_send_authority()
                .map_err(|_| DispatchError::MaybeDispatched)?
                .consume()
                .map_err(|_| {
                    DispatchError::RejectedBeforeEffect(
                        runne_provider::ProviderPreEffectRejection::AdapterRejected,
                    )
                })?;
            if let Some(now) = self.finish_at {
                self.now.store(now, Ordering::SeqCst);
            } else {
                reopen_test_store(&self.path, 100)
                    .begin(revoke(96, "revoke-completed-effect", 2, 2))
                    .unwrap();
            }
            Ok(ProviderStreamId::from_bytes([19; 16]))
        })
    }
}

#[tokio::test]
async fn rejected_publication_cancels_exact_adapter_stream_and_stays_uncertain() {
    verify_cleanup(false, None).await;
}

#[tokio::test]
async fn stalled_local_cancel_does_not_block_uncertain_outcome() {
    verify_cleanup(true, None).await;
}

#[tokio::test]
async fn expired_completed_effect_is_not_published() {
    for now in [99, 220, 221] {
        verify_cleanup(false, Some(now)).await;
    }
}

#[tokio::test]
async fn completed_effect_before_deadline_is_published_without_cancel() {
    verify_cleanup(false, Some(219)).await;
}

async fn verify_cleanup(stall_cancel: bool, finish_at: Option<i64>) {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    secure_directory(directory.path());
    secure_directory(&daemon);
    let path = daemon.join("publication-revoke.sqlite");
    let lifecycle = open_test_store(&path, 100);
    let request = coordinator_request(95, "publication-revoke", &path);
    complete_pair(&lifecycle, 95, "publication-pair");
    let dispatch = SqliteProviderDispatchStore::open_with_connection(
        path.to_str().unwrap(),
        configured_connection(&path),
    )
    .unwrap();
    let now = Arc::new(AtomicI64::new(100));
    let clock = Arc::clone(&now);
    let execution = SqliteProviderExecutionStore::open_with_connection_and_now(
        path.to_str().unwrap(),
        configured_connection(&path),
        Arc::new(move || clock.load(Ordering::SeqCst)),
    )
    .unwrap();
    let launch = execution.activate_runtime_launch(&config()).unwrap();
    super::super::super::online_proof_test_support::arm(&execution);
    let adapter = CompletedAfterRevoke {
        path: path.clone(),
        cancelled: Mutex::new(Vec::new()),
        stall_cancel,
        finish_at,
        now,
    };
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &dispatch,
        &execution,
        CredentialDispatchAuthority::new(&lifecycle, &launch),
        &adapter,
        &adapter,
        &Guard,
    );
    // The bound being asserted is "a stalled local cancel cannot block the
    // uncertain outcome forever", not a wall-clock speed budget: a generous
    // timeout keeps the invariant meaningful on a fully loaded CI host.
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        coordinator.dispatch(request),
    )
    .await
    .expect("local cancellation must be bounded")
    .unwrap();
    if finish_at == Some(219) {
        assert!(matches!(
            outcome,
            crate::provider::ProviderCoordinatorOutcome::Streaming { .. }
        ));
        assert!(adapter.cancelled.lock().unwrap().is_empty());
        return;
    }
    assert_eq!(
        outcome,
        crate::provider::ProviderCoordinatorOutcome::Uncertain
    );
    assert_eq!(
        *adapter.cancelled.lock().unwrap(),
        vec![ProviderStreamId::from_bytes([19; 16])],
    );
    assert_eq!(online_counts(&path), (1, 1, 1));
}
