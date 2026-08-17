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

const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-0000000008a1";
const PROJECT_ID: &str = "018f2e3a-7000-7000-8000-0000000008a2";

struct RetentionLifecycle {
    operations: Arc<tokio::sync::Mutex<()>>,
    reaps: Arc<AtomicUsize>,
}

impl OwnedRuntimeLifecycle for RetentionLifecycle {
    fn stop_on_explicit_quit(&self) {}
}

impl NativeRootAdmissionLifecycle for RetentionLifecycle {
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
        Box::pin(async move {
            assert!(operations.try_lock().is_err(), "reaper lost its permit");
            drop(permit);
        })
    }
}

struct RetainedFixture {
    selections: DirectorySelectionManager,
    prepared: crate::prepared_workspace::PreparedWorkspaceManager,
    reference: crate::prepared_workspace::PreparedWorkspaceRef,
    lifecycle: RuntimeLifecycleManager,
    operations: Arc<tokio::sync::Mutex<()>>,
    reaps: Arc<AtomicUsize>,
    original_deadline: Instant,
    _profile: tempfile::TempDir,
    _root: tempfile::TempDir,
}

async fn retained_fixture(ttl: Duration) -> RetainedFixture {
    let operations = Arc::new(tokio::sync::Mutex::new(()));
    let reaps = Arc::new(AtomicUsize::new(0));
    let child = Arc::new(RetentionLifecycle {
        operations: Arc::clone(&operations),
        reaps: Arc::clone(&reaps),
    });
    let lifecycle = RuntimeLifecycleManager {
        owned_runtime: Some(child.clone()),
        root_admission: Some(child),
        runtime_mode: RuntimeMode::Bundled,
        shutting_down: AtomicBool::new(false),
    };
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let address = listener.local_addr().expect("address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("snapshot");
        let mut bytes = [0; 4096];
        let count = stream.read(&mut bytes).await.expect("snapshot request");
        assert!(
            std::str::from_utf8(&bytes[..count])
                .unwrap()
                .starts_with(&format!("GET /v1/workspaces/{WORKSPACE_ID}"))
        );
        let body = format!(
            r#"{{"workspaceId":"{WORKSPACE_ID}","projectId":"{PROJECT_ID}","displayName":"workspace","version":1,"open":false}}"#
        );
        stream.write_all(format!("HTTP/1.1 200 ok\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.expect("snapshot response");
        let (_, _) = listener.accept().await.expect("bind");
    });
    let profile = tempfile::tempdir().expect("profile");
    let core =
        open_protected_bundled_workspace_core(&profile.path().join("profile.sqlite3"), address)
            .await
            .expect("core");
    let selections = DirectorySelectionManager::new(ttl).expect("selections");
    selections
        .renderer_generations()
        .page_loaded("main")
        .expect("generation");
    let prepared = selections.prepared_workspaces();
    let reserved_at = Instant::now();
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
        .begin_initial(&reference, "main", 1, "request", Instant::now(), &lifecycle)
        .expect("attempt");
    assert_eq!(
        open_prepared_workspace(&core, &lifecycle, attempt)
            .await
            .expect_err("post-send failure")
            .code,
        "prepared_workspace_retryable"
    );
    server.await.expect("server");
    assert!(prepared.retained_for_test(&reference));
    RetainedFixture {
        selections,
        prepared,
        reference,
        lifecycle,
        operations,
        reaps,
        original_deadline: reserved_at + ttl,
        _profile: profile,
        _root: root,
    }
}

#[tokio::test]
async fn retained_expiry_releases_permit_without_reap_or_deadline_extension() {
    let fixture = retained_fixture(Duration::from_secs(1)).await;
    let retry = fixture
        .prepared
        .begin_retry(
            &fixture.reference,
            "main",
            1,
            "request",
            Instant::now(),
            &fixture.lifecycle,
        )
        .expect("retry before expiry");
    drop(retry);
    let until_expiry = fixture
        .original_deadline
        .saturating_duration_since(Instant::now());
    assert!(
        tokio::time::timeout(
            until_expiry + Duration::from_secs(1),
            Arc::clone(&fixture.operations).lock_owned()
        )
        .await
        .is_ok(),
        "original expiry must release the retained permit"
    );
    assert_eq!(fixture.reaps.load(Ordering::Acquire), 0);
    assert!(!fixture.prepared.has_authority_for_test(&fixture.reference));
    assert!(
        fixture
            .prepared
            .begin_retry(
                &fixture.reference,
                "main",
                1,
                "request",
                Instant::now(),
                &fixture.lifecycle
            )
            .is_err()
    );
}

#[tokio::test]
async fn reload_or_destroy_orphans_post_send_authority_and_denies_stale_retry_without_reap() {
    let fixture = retained_fixture(Duration::from_secs(1)).await;
    assert_eq!(
        fixture
            .selections
            .renderer_generations()
            .page_loaded("main")
            .expect("reload"),
        2
    );
    assert!(fixture.prepared.orphaned_for_test(&fixture.reference));
    assert!(!fixture.prepared.has_authority_for_test(&fixture.reference));
    assert_eq!(fixture.reaps.load(Ordering::Acquire), 0);
    assert!(
        fixture.operations.try_lock().is_ok(),
        "reload must release retained authority"
    );
    assert!(
        fixture
            .prepared
            .begin_retry(
                &fixture.reference,
                "main",
                1,
                "request",
                Instant::now(),
                &fixture.lifecycle
            )
            .is_err()
    );
    assert!(
        fixture
            .prepared
            .begin_retry(
                &fixture.reference,
                "main",
                2,
                "request",
                Instant::now(),
                &fixture.lifecycle
            )
            .is_err()
    );
}
