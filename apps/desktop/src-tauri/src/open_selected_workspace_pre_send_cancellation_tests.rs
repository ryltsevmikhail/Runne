use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use runne_app_core::test_support::open_protected_bundled_workspace_core;
use tokio::{io::AsyncReadExt, net::TcpListener, sync::Notify};

use super::*;
use crate::directory_selection_test_support::test_admission_for;

const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-0000000008c1";

struct BlockingReapLifecycle {
    operations: Arc<tokio::sync::Mutex<()>>,
    reaps: Arc<AtomicUsize>,
    started: Arc<Notify>,
    release: Arc<Notify>,
}

impl OwnedRuntimeLifecycle for BlockingReapLifecycle {
    fn stop_on_explicit_quit(&self) {}
}

impl NativeRootAdmissionLifecycle for BlockingReapLifecycle {
    fn prepare_root_admission(
        &self,
        _: VerifiedRootHandle,
        _: WorkspaceId,
        _: u64,
    ) -> RootAdmissionFuture {
        Box::pin(async { Err(AppCoreError::RuntimeUnavailable) })
    }
    fn reap_failed_root_admission(
        &self,
        permit: tokio::sync::OwnedMutexGuard<()>,
    ) -> RootAdmissionReapFuture {
        self.reaps.fetch_add(1, Ordering::AcqRel);
        let operations = Arc::clone(&self.operations);
        let started = Arc::clone(&self.started);
        let release = Arc::clone(&self.release);
        Box::pin(async move {
            assert!(operations.try_lock().is_err(), "reaper must own the permit");
            started.notify_one();
            release.notified().await;
            drop(permit);
        })
    }
}

#[tokio::test]
async fn pre_send_cancellation_reaps_once_and_holds_permit_until_async_reaper_finishes() {
    let operations = Arc::new(tokio::sync::Mutex::new(()));
    let reaps = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let child = Arc::new(BlockingReapLifecycle {
        operations: Arc::clone(&operations),
        reaps: Arc::clone(&reaps),
        started: Arc::clone(&started),
        release: Arc::clone(&release),
    });
    let lifecycle = Arc::new(RuntimeLifecycleManager {
        owned_runtime: Some(child.clone()),
        root_admission: Some(child),
        runtime_mode: RuntimeMode::Bundled,
        shutting_down: AtomicBool::new(false),
    });
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let address = listener.local_addr().expect("address");
    let request_started = Arc::new(Notify::new());
    let server_signal = Arc::clone(&request_started);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("get");
        let mut bytes = [0; 4096];
        let count = stream.read(&mut bytes).await.expect("read");
        assert!(count > 0, "request must not be empty");
        server_signal.notify_one();
        std::future::pending::<()>().await;
    });
    let profile = tempfile::tempdir().expect("profile");
    let core =
        open_protected_bundled_workspace_core(&profile.path().join("profile.sqlite3"), address)
            .await
            .expect("core");
    let selections = DirectorySelectionManager::new(Duration::from_secs(1)).expect("selections");
    selections
        .renderer_generations()
        .page_loaded("main")
        .expect("generation");
    let prepared = selections.prepared_workspaces();
    let reference = prepared
        .reserve(
            PreparedWorkspaceBinding::new(
                "main",
                1,
                "request",
                WORKSPACE_ID.parse().expect("workspace"),
                1,
            )
            .expect("binding"),
            Instant::now(),
        )
        .expect("reserve");
    let root = tempfile::tempdir().expect("root");
    let mut permit = Some(Arc::clone(&operations).lock_owned().await);
    prepared
        .commit(
            &reference,
            crate::directory_selection_test_support::test_root_handle(root.path()),
            test_admission_for(WORKSPACE_ID.parse().expect("workspace"), 1),
            &mut permit,
            Instant::now(),
        )
        .expect("commit");
    let attempt = prepared
        .begin_initial(&reference, "main", 1, "request", Instant::now(), &lifecycle)
        .expect("attempt");
    let task_lifecycle = Arc::clone(&lifecycle);
    let task =
        tokio::spawn(async move { open_prepared_workspace(&core, &task_lifecycle, attempt).await });
    request_started.notified().await;
    task.abort();
    let _ = task.await;
    started.notified().await;
    assert_eq!(reaps.load(Ordering::Acquire), 1);
    assert!(
        operations.try_lock().is_err(),
        "permit released before reaper completion"
    );
    release.notify_one();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), Arc::clone(&operations).lock_owned())
            .await
            .is_ok()
    );
    assert_eq!(reaps.load(Ordering::Acquire), 1);
    server.abort();
}
