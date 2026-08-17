use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use gocode_app_core::test_support::open_protected_bundled_workspace_core;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Notify,
};

use super::*;
use crate::directory_selection_test_support::test_admission;

const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-000000000891";
const PROJECT_ID: &str = "018f2e3a-7000-7000-8000-000000000892";

struct StopLifecycle {
    reaps: Arc<AtomicUsize>,
    stops: Arc<AtomicUsize>,
}

impl OwnedRuntimeLifecycle for StopLifecycle {
    fn stop_on_explicit_quit(&self) {
        self.stops.fetch_add(1, Ordering::AcqRel);
    }
}

impl NativeRootAdmissionLifecycle for StopLifecycle {
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
        Box::pin(async move { drop(permit) })
    }
}

fn lifecycle(reaps: Arc<AtomicUsize>, stops: Arc<AtomicUsize>) -> RuntimeLifecycleManager {
    let lifecycle = Arc::new(StopLifecycle { reaps, stops });
    RuntimeLifecycleManager {
        owned_runtime: Some(lifecycle.clone()),
        root_admission: Some(lifecycle),
        runtime_mode: RuntimeMode::Bundled,
        shutting_down: AtomicBool::new(false),
    }
}

fn snapshot() -> String {
    format!(
        r#"{{"workspaceId":"{WORKSPACE_ID}","projectId":"{PROJECT_ID}","displayName":"workspace","version":1,"open":false}}"#
    )
}

#[tokio::test]
async fn explicit_stop_fences_inflight_post_send_and_drop_cannot_reinsert() {
    let operations = Arc::new(tokio::sync::Mutex::new(()));
    let reaps = Arc::new(AtomicUsize::new(0));
    let stops = Arc::new(AtomicUsize::new(0));
    let lifecycle = Arc::new(lifecycle(Arc::clone(&reaps), Arc::clone(&stops)));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let address = listener.local_addr().expect("address");
    let bind_started = Arc::new(Notify::new());
    let release_bind = Arc::new(Notify::new());
    let server_signal = Arc::clone(&bind_started);
    let server_release = Arc::clone(&release_bind);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("initial get");
        let mut bytes = [0; 4096];
        let count = stream.read(&mut bytes).await.expect("initial request");
        assert!(
            std::str::from_utf8(&bytes[..count])
                .expect("initial request")
                .starts_with(&format!("GET /v1/workspaces/{WORKSPACE_ID}"))
        );
        let body = snapshot();
        stream
            .write_all(format!("HTTP/1.1 200 ok\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes())
            .await
            .expect("snapshot");
        let (mut stream, _) = listener.accept().await.expect("bind");
        let count = stream.read(&mut bytes).await.expect("bind request");
        assert!(
            std::str::from_utf8(&bytes[..count])
                .expect("bind request")
                .starts_with(&format!("POST /v1/workspaces/{WORKSPACE_ID}/root-bindings"))
        );
        server_signal.notify_one();
        server_release.notified().await;
        drop(stream);
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
    let task_lifecycle = Arc::clone(&lifecycle);
    let task =
        tokio::spawn(async move { open_prepared_workspace(&core, &task_lifecycle, attempt).await });

    bind_started.notified().await;
    assert!(
        lifecycle.begin_explicit_quit(),
        "explicit quit owns the stop sequence"
    );
    selections.clear_pending_authority();
    lifecycle.stop_owned_runtime();
    release_bind.notify_one();
    let error = task
        .await
        .expect("task")
        .expect_err("explicit stop rejects retry");
    server.await.expect("server");

    assert_eq!(reaps.load(Ordering::Acquire), 0);
    assert_eq!(stops.load(Ordering::Acquire), 1);
    assert_eq!(error.code, "prepared_workspace_rejected");
    assert!(
        operations.try_lock().is_ok(),
        "stop/drop must release the permit"
    );
    assert!(
        prepared
            .begin_retry(&reference, "main", 1, "request", Instant::now(), &lifecycle)
            .is_err()
    );
    assert!(!prepared.retained_for_test(&reference));
    assert!(!prepared.has_authority_for_test(&reference));
}
