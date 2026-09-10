use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use runne_app_core::test_support::open_protected_bundled_workspace_core;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Notify,
};

use super::*;
use crate::directory_selection_test_support::test_admission;

const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-000000000881";
const PROJECT_ID: &str = "018f2e3a-7000-7000-8000-000000000882";

struct CancellationLifecycle {
    operations: Arc<tokio::sync::Mutex<()>>,
    reaps: Arc<AtomicUsize>,
    reaper_saw_exact_permit: Arc<AtomicBool>,
}

impl OwnedRuntimeLifecycle for CancellationLifecycle {
    fn stop_on_explicit_quit(&self) {}
}

impl NativeRootAdmissionLifecycle for CancellationLifecycle {
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
        let operations = Arc::clone(&self.operations);
        let reaper_saw_exact_permit = Arc::clone(&self.reaper_saw_exact_permit);
        self.reaps.fetch_add(1, Ordering::AcqRel);
        Box::pin(async move {
            // The reaper owns the exact permit: while it holds the operations
            // permit, operations stays locked, so try_lock() must fail. A
            // foreign permit (from another mutex) would leave operations free
            // and try_lock() would succeed. Publish the observation instead of
            // asserting: this future is detached, so the parent test must
            // inspect the result after the lock is released.
            reaper_saw_exact_permit.store(operations.try_lock().is_err(), Ordering::SeqCst);
            drop(permit);
        })
    }
}

fn lifecycle(
    operations: Arc<tokio::sync::Mutex<()>>,
    reaps: Arc<AtomicUsize>,
    reaper_saw_exact_permit: Arc<AtomicBool>,
) -> RuntimeLifecycleManager {
    let lifecycle = Arc::new(CancellationLifecycle {
        operations,
        reaps,
        reaper_saw_exact_permit,
    });
    RuntimeLifecycleManager {
        owned_runtime: Some(lifecycle.clone()),
        root_admission: Some(lifecycle),
        runtime_mode: RuntimeMode::Bundled,
        shutting_down: AtomicBool::new(false),
    }
}

fn snapshot(version: u64) -> String {
    format!(
        r#"{{"workspaceId":"{WORKSPACE_ID}","projectId":"{PROJECT_ID}","displayName":"workspace","version":{version},"open":false}}"#
    )
}

#[tokio::test]
async fn cancellation_after_possible_bind_send_retains_the_exact_child_for_retry() {
    let operations = Arc::new(tokio::sync::Mutex::new(()));
    let reaps = Arc::new(AtomicUsize::new(0));
    let lifecycle = lifecycle(
        Arc::clone(&operations),
        Arc::clone(&reaps),
        Arc::new(AtomicBool::new(false)),
    );
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let address = listener.local_addr().expect("address");
    let bind_started = Arc::new(Notify::new());
    let server_signal = Arc::clone(&bind_started);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("get");
        let mut bytes = [0; 4096];
        let count = stream.read(&mut bytes).await.expect("read");
        assert!(
            std::str::from_utf8(&bytes[..count])
                .unwrap()
                .starts_with(&format!("GET /v1/workspaces/{WORKSPACE_ID}"))
        );
        let body = snapshot(1);
        stream.write_all(format!("HTTP/1.1 200 ok\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.expect("snapshot");
        let (_, _) = listener.accept().await.expect("bind");
        server_signal.notify_one();
        std::future::pending::<()>().await;
    });
    let profile = tempfile::tempdir().expect("profile");
    let core =
        open_protected_bundled_workspace_core(&profile.path().join("profile.sqlite3"), address)
            .await
            .expect("core");
    let selections = DirectorySelectionManager::new(Duration::from_secs(30)).expect("selections");
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
            test_admission(),
            &mut permit,
            Instant::now(),
        )
        .expect("commit");
    let attempt = prepared
        .consume_for_open(&reference, "main", 1, "request", Instant::now(), &lifecycle)
        .expect("attempt");
    let task =
        tokio::spawn(async move { open_prepared_workspace(&core, &lifecycle, attempt).await });
    bind_started.notified().await;
    task.abort();
    let _ = task.await;
    assert_eq!(reaps.load(Ordering::Acquire), 0);
    assert!(
        operations.try_lock().is_err(),
        "retained child released its permit"
    );
    let retry_lifecycle = super::open_selected_workspace_cancellation_tests::lifecycle(
        Arc::clone(&operations),
        Arc::clone(&reaps),
        Arc::new(AtomicBool::new(false)),
    );
    assert!(
        prepared
            .begin_retry(
                &reference,
                "main",
                1,
                "request",
                Instant::now(),
                &retry_lifecycle
            )
            .is_ok()
    );
    server.abort();
}

#[tokio::test]
async fn initial_and_retry_are_single_attempt_exact_bindings() {
    let selections = DirectorySelectionManager::new(Duration::from_secs(30)).expect("selections");
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
    let directory = tempfile::tempdir().expect("directory");
    let operations = Arc::new(tokio::sync::Mutex::new(()));
    let mut permit = Some(Arc::clone(&operations).lock_owned().await);
    prepared
        .commit(
            &reference,
            crate::directory_selection_test_support::test_root_handle(directory.path()),
            test_admission(),
            &mut permit,
            Instant::now(),
        )
        .expect("commit");
    let reaps = Arc::new(AtomicUsize::new(0));
    let reaper_saw_exact_permit = Arc::new(AtomicBool::new(false));
    let lifecycle = lifecycle(
        Arc::clone(&operations),
        Arc::clone(&reaps),
        Arc::clone(&reaper_saw_exact_permit),
    );
    assert!(
        prepared
            .begin_initial(&reference, "main", 1, "wrong", Instant::now(), &lifecycle)
            .is_err()
    );
    let first = prepared
        .begin_initial(&reference, "main", 1, "request", Instant::now(), &lifecycle)
        .expect("initial");
    assert!(
        prepared
            .begin_initial(&reference, "main", 1, "request", Instant::now(), &lifecycle)
            .is_err()
    );
    assert!(
        prepared
            .begin_retry(&reference, "main", 1, "request", Instant::now(), &lifecycle)
            .is_err()
    );
    drop(first);
    let released = tokio::time::timeout(Duration::from_secs(1), Arc::clone(&operations).lock_owned())
        .await
        .expect("reaper must release the exact permit");
    assert_eq!(reaps.load(Ordering::Acquire), 1);
    assert!(
        reaper_saw_exact_permit.load(Ordering::Acquire),
        "reaper must have observed the exact operations permit"
    );
    drop(released);
}
