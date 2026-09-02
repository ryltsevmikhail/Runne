use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use runne_app_core::test_support::open_protected_bundled_workspace_core;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use super::*;
use crate::directory_selection_test_support::test_admission;
use super::open_selected_workspace_tests::{
    lifecycle, workspace_reconcile, workspace_snapshot, WORKSPACE_ID,
};

#[tokio::test]
async fn post_bind_failure_retains_the_exact_prepared_open_for_retry() {
    let operations = Arc::new(tokio::sync::Mutex::new(()));
    let reaps = Arc::new(AtomicUsize::new(0));
    let lifecycle = lifecycle(Arc::clone(&operations), Arc::clone(&reaps));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let address = listener.local_addr().expect("loopback origin");
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for (index, (status, body)) in [
            (200, workspace_snapshot(1, false)),
            (202, format!(r#"{{"workspaceId":"{WORKSPACE_ID}","newVersion":2}}"#)),
            (200, r#"{"disposition":"not_committed_retryable"}"#.to_owned()),
            (202, format!(r#"{{"workspaceId":"{WORKSPACE_ID}","newVersion":2}}"#)),
            (200, workspace_reconcile("bind_workspace_root", 2)),
            (202, format!(r#"{{"workspaceId":"{WORKSPACE_ID}","newVersion":3}}"#)),
            (200, workspace_reconcile("open_workspace", 3)),
            (200, workspace_snapshot(3, true)),
        ]
        .into_iter()
        .enumerate()
        {
            let (mut stream, _) = listener.accept().await.expect("request");
            let mut bytes = [0; 8192];
            let count = stream.read(&mut bytes).await.expect("request");
            requests.push(bytes[..count].to_vec());
            if index != 1 {
                let response = format!("HTTP/1.1 {status} test\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                stream.write_all(response.as_bytes()).await.expect("response");
            }
        }
        requests
    });
    let profile = tempfile::tempdir().expect("profile");
    let core = open_protected_bundled_workspace_core(&profile.path().join("profile.sqlite3"), address).await.expect("core");
    let selections = DirectorySelectionManager::new(Duration::from_secs(30)).expect("selections");
    selections.renderer_generations().page_loaded("main").expect("generation");
    let prepared = selections.prepared_workspaces();
    let reference = prepared.reserve(PreparedWorkspaceBinding::new("main", 1, "request", WORKSPACE_ID.parse().expect("workspace"), 1).expect("binding"), Instant::now()).expect("reserve");
    let root = tempfile::tempdir().expect("root");
    let mut permit = Some(Arc::clone(&operations).lock_owned().await);
    prepared.commit(&reference, crate::directory_selection_test_support::test_root_handle(root.path()), test_admission(), &mut permit, Instant::now()).expect("commit");
    drop(selections);
    let attempt = prepared.consume_for_open(&reference, "main", 1, "request", Instant::now(), &lifecycle).expect("consume");
    assert!(open_prepared_workspace(&core, &lifecycle, attempt).await.is_err());
    assert_eq!(reaps.load(Ordering::Acquire), 0);
    assert!(operations.try_lock().is_err());
    let retry = prepared.begin_retry(&reference, "main", 1, "request", Instant::now(), &lifecycle).expect("retained retry");
    assert!(open_prepared_workspace(&core, &lifecycle, retry).await.is_ok());
    drop(prepared);
    assert_eq!(reaps.load(Ordering::Acquire), 0);
    let requests = server.await.expect("server");
    assert_eq!(requests[1], requests[3], "retry must reuse exact bind bytes");
}
