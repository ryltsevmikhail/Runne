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

pub const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-000000000861";
pub const PROJECT_ID: &str = "018f2e3a-7000-7000-8000-000000000862";

struct ReapLifecycle {
    operations: Arc<tokio::sync::Mutex<()>>,
    reaps: Arc<AtomicUsize>,
}

impl OwnedRuntimeLifecycle for ReapLifecycle {
    fn connect_runtime(&self) -> RuntimeConnectionFuture<'_> {
        Box::pin(async { Ok(RuntimeAvailability::Live) })
    }

    fn stop_on_explicit_quit(&self) {}
}

impl NativeRootAdmissionLifecycle for ReapLifecycle {
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
        self.reaps.fetch_add(1, Ordering::AcqRel);
        Box::pin(async move {
            assert!(
                operations.try_lock().is_err(),
                "reap did not receive the exact child permit"
            );
            drop(permit);
        })
    }
}

pub fn workspace_snapshot(version: u64, open: bool) -> String {
    format!(
        r#"{{"workspaceId":"{WORKSPACE_ID}","projectId":"{PROJECT_ID}","displayName":"workspace","version":{version},"open":{open}}}"#
    )
}

pub fn workspace_reconcile(operation: &str, version: u64) -> String {
    format!(
        r#"{{"disposition":"durably_recorded","outcome":{{"operation":"{operation}","workspaceId":"{WORKSPACE_ID}","newVersion":{version}}}}}"#
    )
}

async fn server(listener: TcpListener, operations: Arc<tokio::sync::Mutex<()>>, wrong_bind: bool) {
    for (status, body) in [
        (200, workspace_snapshot(1, false)),
        (
            202,
            format!(
                r#"{{"workspaceId":"{}","newVersion":2}}"#,
                if wrong_bind {
                    "018f2e3a-7000-7000-8000-000000000863"
                } else {
                    WORKSPACE_ID
                }
            ),
        ),
        (200, workspace_reconcile("bind_workspace_root", 2)),
        (
            202,
            format!(r#"{{"workspaceId":"{WORKSPACE_ID}","newVersion":3}}"#),
        ),
        (200, workspace_reconcile("open_workspace", 3)),
        (200, workspace_snapshot(3, true)),
    ] {
        let (mut stream, _) = listener.accept().await.expect("request");
        assert!(
            operations.try_lock().is_err(),
            "permit was dropped before final GET"
        );
        let mut bytes = [0; 8192];
        let count = stream.read(&mut bytes).await.expect("request");
        let request = std::str::from_utf8(&bytes[..count]).expect("request");
        let expected = match status {
            200 if body.contains("\"disposition\"") => {
                "POST /v1/commands/reconcile HTTP/1.1".to_owned()
            }
            200 if body.contains("\"open\":false") => {
                format!("GET /v1/workspaces/{WORKSPACE_ID} HTTP/1.1")
            }
            200 => format!("GET /v1/workspaces/{WORKSPACE_ID} HTTP/1.1"),
            202 if body.contains("newVersion\":2") => {
                format!("POST /v1/workspaces/{WORKSPACE_ID}/root-bindings HTTP/1.1")
            }
            202 => format!("POST /v1/workspaces/{WORKSPACE_ID}/open HTTP/1.1"),
            _ => unreachable!("fixture status"),
        };
        assert!(
            request.starts_with(&expected),
            "unexpected method or path: {request}"
        );
        let response = format!(
            "HTTP/1.1 {status} test\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("response");
        if wrong_bind {
            break;
        }
    }
}

async fn prepared_value(
    operations: Arc<tokio::sync::Mutex<()>>,
    lifecycle: &RuntimeLifecycleManager,
) -> (
    tempfile::TempDir,
    crate::prepared_workspace::PreparedWorkspaceOpenAttempt,
) {
    let selections = DirectorySelectionManager::new(Duration::from_secs(30)).expect("selections");
    assert_eq!(
        selections
            .renderer_generations()
            .page_loaded("main")
            .expect("generation"),
        1
    );
    let prepared = selections.prepared_workspaces();
    let reference = prepared
        .reserve(
            PreparedWorkspaceBinding::new(
                "main",
                1,
                "request",
                WORKSPACE_ID.parse().expect("workspace id"),
                1,
            )
            .expect("binding"),
            Instant::now(),
        )
        .expect("reserve");
    let directory = tempfile::tempdir().expect("directory");
    let root = crate::directory_selection_test_support::test_root_handle(directory.path());
    let mut permit = Some(Arc::clone(&operations).lock_owned().await);
    prepared
        .commit(
            &reference,
            root,
            test_admission(),
            &mut permit,
            Instant::now(),
        )
        .expect("commit");
    let value = prepared
        .consume_for_open(&reference, "main", 1, "request", Instant::now(), lifecycle)
        .expect("consume");
    drop(prepared);
    drop(selections);
    (directory, value)
}

pub fn lifecycle(
    operations: Arc<tokio::sync::Mutex<()>>,
    reaps: Arc<AtomicUsize>,
) -> RuntimeLifecycleManager {
    let lifecycle = Arc::new(ReapLifecycle { operations, reaps });
    RuntimeLifecycleManager {
        owned_runtime: Some(lifecycle.clone()),
        root_admission: Some(lifecycle),
        runtime_mode: RuntimeMode::Bundled,
        shutting_down: AtomicBool::new(false),
    }
}

#[tokio::test]
async fn prepared_permit_spans_bind_open_and_final_get_and_post_bind_never_reaps() {
    let operations = Arc::new(tokio::sync::Mutex::new(()));
    let reaps = Arc::new(AtomicUsize::new(0));
    let lifecycle = lifecycle(Arc::clone(&operations), Arc::clone(&reaps));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let address = listener.local_addr().expect("loopback origin");
    let server = tokio::spawn(server(listener, Arc::clone(&operations), false));
    let directory = tempfile::tempdir().expect("profile");
    let core =
        open_protected_bundled_workspace_core(&directory.path().join("profile.sqlite3"), address)
            .await
            .expect("core");
    let (_root, value) = prepared_value(Arc::clone(&operations), &lifecycle).await;
    assert!(
        open_prepared_workspace(&core, &lifecycle, value)
            .await
            .is_ok()
    );
    server.await.expect("server");
    assert_eq!(reaps.load(Ordering::Acquire), 0);
    assert!(operations.try_lock().is_ok());
}

#[tokio::test]
async fn only_a_pre_send_failure_reaps_the_exact_prepared_child() {
    let operations = Arc::new(tokio::sync::Mutex::new(()));
    let reaps = Arc::new(AtomicUsize::new(0));
    let lifecycle = lifecycle(Arc::clone(&operations), Arc::clone(&reaps));
    let directory = tempfile::tempdir().expect("profile");
    let core = open_protected_bundled_workspace_core(
        &directory.path().join("profile.sqlite3"),
        "127.0.0.1:1".parse().expect("loopback origin"),
    )
    .await
    .expect("core");
    let (_root, value) = prepared_value(Arc::clone(&operations), &lifecycle).await;
    assert!(
        open_prepared_workspace(&core, &lifecycle, value)
            .await
            .is_err()
    );
    assert_eq!(reaps.load(Ordering::Acquire), 1);
    assert!(operations.try_lock().is_ok());
}

#[tokio::test]
async fn post_bind_wrong_ack_retains_permit_without_reap() {
    let operations = Arc::new(tokio::sync::Mutex::new(()));
    let reaps = Arc::new(AtomicUsize::new(0));
    let lifecycle = lifecycle(Arc::clone(&operations), Arc::clone(&reaps));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let address = listener.local_addr().expect("loopback origin");
    let server = tokio::spawn(server(listener, Arc::clone(&operations), true));
    let directory = tempfile::tempdir().expect("profile");
    let core =
        open_protected_bundled_workspace_core(&directory.path().join("profile.sqlite3"), address)
            .await
            .expect("core");
    let (_root, value) = prepared_value(Arc::clone(&operations), &lifecycle).await;
    assert!(
        open_prepared_workspace(&core, &lifecycle, value)
            .await
            .is_err()
    );
    server.await.expect("server");
    assert_eq!(reaps.load(Ordering::Acquire), 0);
    assert!(operations.try_lock().is_err());
}
