use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use gocode_app_core::test_support::open_protected_bundled_workspace_core;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use super::*;
use crate::directory_selection_test_support::test_admission;

const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-0000000008b1";
const PROJECT_ID: &str = "018f2e3a-7000-7000-8000-0000000008b2";

struct TerminalLifecycle;

impl OwnedRuntimeLifecycle for TerminalLifecycle {
    fn stop_on_explicit_quit(&self) {}
}

impl NativeRootAdmissionLifecycle for TerminalLifecycle {
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
        Box::pin(async move { drop(permit) })
    }
}

fn lifecycle() -> RuntimeLifecycleManager {
    let child = Arc::new(TerminalLifecycle);
    RuntimeLifecycleManager {
        owned_runtime: Some(child.clone()),
        root_admission: Some(child),
        runtime_mode: RuntimeMode::Bundled,
        shutting_down: AtomicBool::new(false),
    }
}

fn snapshot(version: u64, open: bool) -> String {
    format!(
        r#"{{"workspaceId":"{WORKSPACE_ID}","projectId":"{PROJECT_ID}","displayName":"workspace","version":{version},"open":{open}}}"#
    )
}

fn reconcile(operation: &str, version: u64) -> String {
    format!(
        r#"{{"disposition":"durably_recorded","outcome":{{"operation":"{operation}","workspaceId":"{WORKSPACE_ID}","newVersion":{version}}}}}"#
    )
}

#[tokio::test]
async fn opened_reference_is_terminal_and_swept_at_its_original_deadline_without_extra_dispatch() {
    let requests = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let address = listener.local_addr().expect("address");
    let server_requests = Arc::clone(&requests);
    let server = tokio::spawn(async move {
        for (index, (status, body)) in [
            (200, snapshot(1, false)),
            (
                202,
                format!(r#"{{"workspaceId":"{WORKSPACE_ID}","newVersion":2}}"#),
            ),
            (200, reconcile("bind_workspace_root", 2)),
            (
                202,
                format!(r#"{{"workspaceId":"{WORKSPACE_ID}","newVersion":3}}"#),
            ),
            (200, reconcile("open_workspace", 3)),
            (200, snapshot(3, true)),
        ]
        .into_iter()
        .enumerate()
        {
            let (mut stream, _) = listener.accept().await.expect("request");
            server_requests.fetch_add(1, Ordering::AcqRel);
            let mut bytes = [0; 4096];
            let count = stream.read(&mut bytes).await.expect("read");
            assert!(count > 0, "request must not be empty");
            if index == 0 {
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
            stream.write_all(format!("HTTP/1.1 {status} ok\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.expect("response");
        }
    });
    let profile = tempfile::tempdir().expect("profile");
    let core =
        open_protected_bundled_workspace_core(&profile.path().join("profile.sqlite3"), address)
            .await
            .expect("core");
    let ttl = Duration::from_millis(100);
    let reserved_at = Instant::now();
    let selections = DirectorySelectionManager::new(ttl).expect("selections");
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
            reserved_at,
        )
        .expect("reserve");
    let root = tempfile::tempdir().expect("root");
    let operations = Arc::new(tokio::sync::Mutex::new(()));
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
    let lifecycle = lifecycle();
    let attempt = prepared
        .begin_initial(&reference, "main", 1, "request", Instant::now(), &lifecycle)
        .expect("initial");
    assert!(
        open_prepared_workspace(&core, &lifecycle, attempt)
            .await
            .is_ok()
    );
    server.await.expect("server");
    assert_eq!(requests.load(Ordering::Acquire), 6);
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
    assert_eq!(
        requests.load(Ordering::Acquire),
        6,
        "terminal replay must not dispatch"
    );
    let until_expiry = reserved_at + ttl;
    tokio::time::sleep(
        until_expiry.saturating_duration_since(Instant::now()) + Duration::from_millis(20),
    )
    .await;
    assert!(!prepared.has_entry_for_test(&reference));
}
