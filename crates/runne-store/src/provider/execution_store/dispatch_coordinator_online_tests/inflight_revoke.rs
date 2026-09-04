use super::*;
use crate::provider::credential_lifecycle::online_test_support::revoke;
use std::sync::atomic::AtomicBool;

mod publication_cleanup;

struct PendingEffect {
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    dropped: Arc<AtomicBool>,
}

struct WaitOwner(Arc<AtomicBool>);
impl Drop for WaitOwner {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

impl ProviderEffectPort for PendingEffect {
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
        _: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async move {
            let _owner = WaitOwner(Arc::clone(&self.dropped));
            self.entered
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send(())
                .unwrap();
            std::future::pending().await
        })
    }
}

#[tokio::test]
async fn committed_revoke_interrupts_pending_coordinator_effect_as_uncertain() {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon).unwrap();
    secure_directory(directory.path());
    secure_directory(&daemon);
    let path = daemon.join("inflight-revoke.sqlite");
    let lifecycle = open_test_store(&path, 100);
    complete_pair(&lifecycle, 93, "inflight-pair");
    let dispatch = SqliteProviderDispatchStore::open_with_connection(
        path.to_str().unwrap(),
        configured_connection(&path),
    )
    .unwrap();
    let execution = SqliteProviderExecutionStore::open_with_connection(
        path.to_str().unwrap(),
        configured_connection(&path),
    )
    .unwrap();
    let launch = execution.activate_runtime_launch(&config()).unwrap();
    super::super::online_proof_test_support::arm(&execution);
    let provider_port = Effect::default();
    let (entered, started) = tokio::sync::oneshot::channel();
    let dropped = Arc::new(AtomicBool::new(false));
    let effect = PendingEffect {
        entered: Mutex::new(Some(entered)),
        dropped: Arc::clone(&dropped),
    };
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &dispatch,
        &execution,
        CredentialDispatchAuthority::new(&lifecycle, &launch),
        &provider_port,
        &effect,
        &Guard,
    );
    let run = async {
        tokio::join!(
            coordinator.dispatch(coordinator_request(93, "inflight-revoke")),
            async {
                started.await.unwrap();
                let fencing = reopen_test_store(&path, 100);
                fencing
                    .begin(revoke(94, "revoke-pending-effect", 2, 2))
                    .unwrap();
            },
        )
        .0
    };
    let result = tokio::time::timeout(std::time::Duration::from_secs(2), run).await;
    assert_eq!(
        result.unwrap().unwrap(),
        crate::provider::ProviderCoordinatorOutcome::Uncertain
    );
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(online_counts(&path), (1, 1, 1));
}
