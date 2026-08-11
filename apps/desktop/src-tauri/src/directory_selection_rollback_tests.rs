#![allow(clippy::significant_drop_tightening)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::*;
use crate::prepared_workspace::PreparedWorkspaceRef;

fn test_admission() -> RootHandleAdmission {
    RootHandleAdmission::decode_token(&format!("gocode-root-admission-v2.{}", "A".repeat(343)))
        .unwrap()
}

struct RollbackLifecycle(Arc<tokio::sync::Mutex<()>>, Arc<AtomicUsize>);
impl OwnedRuntimeLifecycle for RollbackLifecycle {
    fn connect_runtime(&self) -> RuntimeConnectionFuture<'_> {
        Box::pin(async { Ok(RuntimeAvailability::Live) })
    }
    fn stop_on_explicit_quit(&self) {}
}
impl NativeRootAdmissionLifecycle for RollbackLifecycle {
    fn prepare_root_admission(
        &self,
        root: VerifiedRootHandle,
        _: WorkspaceId,
        _: u64,
    ) -> RootAdmissionFuture {
        let operations = Arc::clone(&self.0);
        Box::pin(async move {
            let admission = RootHandleAdmission::decode_token(&format!(
                "gocode-root-admission-v2.{}",
                "A".repeat(343)
            ))
            .unwrap();
            Ok(NativeRootAdmission {
                root,
                admission,
                operation_permit: operations.lock_owned().await,
            })
        })
    }
    fn reap_failed_root_admission(
        &self,
        permit: tokio::sync::OwnedMutexGuard<()>,
    ) -> RootAdmissionReapFuture {
        let operations = Arc::clone(&self.0);
        self.1.fetch_add(1, Ordering::AcqRel);
        Box::pin(async move {
            assert!(operations.try_lock().is_err());
            drop(permit);
        })
    }
}

#[tokio::test]
async fn failed_commit_reaps_under_its_permit_without_global_shutdown() {
    let mock = Arc::new(RollbackLifecycle(
        Arc::new(tokio::sync::Mutex::new(())),
        Arc::new(AtomicUsize::new(0)),
    ));
    let lifecycle = RuntimeLifecycleManager {
        owned_runtime: Some(mock.clone()),
        root_admission: Some(mock.clone()),
        runtime_mode: RuntimeMode::Bundled,
        shutting_down: AtomicBool::new(false),
    };
    let selections = DirectorySelectionManager::new(Duration::from_secs(30)).unwrap();
    assert_eq!(
        selections
            .renderer_generations()
            .page_loaded("main")
            .unwrap(),
        1
    );
    let prepared = selections.prepared_workspaces();
    let reservation = prepared
        .reserve_guard(
            PreparedWorkspaceBinding::new(
                "main",
                1,
                "request",
                WorkspaceId::from_bytes([4; 16]),
                1,
            )
            .unwrap(),
            Instant::now(),
        )
        .unwrap();
    assert_eq!(
        selections
            .renderer_generations()
            .page_loaded("main")
            .unwrap(),
        2
    );
    let directory = tempfile::tempdir().unwrap();
    let root = VerifiedRootHandle::open(directory.path()).unwrap();
    assert!(
        commit_prepared_admission(
            &prepared,
            reservation,
            lifecycle
                .prepare_root_admission(root, WorkspaceId::from_bytes([4; 16]), 1)
                .await
                .unwrap(),
            &lifecycle,
        )
        .await
        .is_err()
    );
    assert_eq!(mock.1.load(Ordering::Acquire), 1);
    assert!(mock.0.try_lock().is_ok());
    assert!(!lifecycle.is_shutting_down());
    let directory = tempfile::tempdir().unwrap();
    let root = VerifiedRootHandle::open(directory.path()).unwrap();
    drop(
        lifecycle
            .prepare_root_admission(root, WorkspaceId::from_bytes([4; 16]), 1)
            .await
            .unwrap(),
    );
    assert_eq!(
        OwnedRuntimeLifecycle::connect_runtime(&*mock)
            .await
            .unwrap(),
        RuntimeAvailability::Live
    );
}

#[tokio::test]
async fn prepared_workspace_retains_its_operation_permit_until_consumed_value_drops() {
    let mock = Arc::new(RollbackLifecycle(
        Arc::new(tokio::sync::Mutex::new(())),
        Arc::new(AtomicUsize::new(0)),
    ));
    let lifecycle = RuntimeLifecycleManager {
        owned_runtime: Some(mock.clone()),
        root_admission: Some(mock.clone()),
        runtime_mode: RuntimeMode::Bundled,
        shutting_down: AtomicBool::new(false),
    };
    let selections = DirectorySelectionManager::new(Duration::from_secs(30)).unwrap();
    assert_eq!(
        selections
            .renderer_generations()
            .page_loaded("main")
            .unwrap(),
        1
    );
    let prepared = selections.prepared_workspaces();
    let reservation = prepared
        .reserve_guard(
            PreparedWorkspaceBinding::new(
                "main",
                1,
                "request",
                WorkspaceId::from_bytes([4; 16]),
                1,
            )
            .unwrap(),
            Instant::now(),
        )
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let root = VerifiedRootHandle::open(directory.path()).unwrap();
    let response = commit_prepared_admission(
        &prepared,
        reservation,
        lifecycle
            .prepare_root_admission(root, WorkspaceId::from_bytes([4; 16]), 1)
            .await
            .unwrap(),
        &lifecycle,
    )
    .await
    .unwrap();
    assert!(mock.0.try_lock().is_err());
    let value = serde_json::to_value(response).unwrap();
    let reference =
        serde_json::from_value::<PreparedWorkspaceRef>(value["reference"].clone()).unwrap();
    let native = prepared
        .consume(&reference, "main", 1, "request", Instant::now())
        .unwrap();
    assert!(mock.0.try_lock().is_err());
    drop(native);
    assert!(mock.0.try_lock().is_ok());
}

#[tokio::test]
async fn page_load_and_expiry_drop_retained_prepared_operation_permits() {
    let selections = DirectorySelectionManager::new(Duration::from_secs(30)).unwrap();
    let generations = selections.renderer_generations();
    assert_eq!(generations.page_loaded("main").unwrap(), 1);
    let prepared = selections.prepared_workspaces();
    let operations = Arc::new(tokio::sync::Mutex::new(()));
    let reservation = prepared
        .reserve(
            PreparedWorkspaceBinding::new("main", 1, "reload", WorkspaceId::from_bytes([4; 16]), 1)
                .unwrap(),
            Instant::now(),
        )
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let root = VerifiedRootHandle::open(directory.path()).unwrap();
    let mut permit = Some(Arc::clone(&operations).lock_owned().await);
    prepared
        .commit(
            &reservation,
            root,
            test_admission(),
            &mut permit,
            Instant::now(),
        )
        .unwrap();
    assert!(operations.try_lock().is_err());
    assert_eq!(generations.page_loaded("main").unwrap(), 2);
    assert!(operations.try_lock().is_ok());

    let reservation = prepared
        .reserve(
            PreparedWorkspaceBinding::new("main", 2, "expiry", WorkspaceId::from_bytes([4; 16]), 1)
                .unwrap(),
            Instant::now(),
        )
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let root = VerifiedRootHandle::open(directory.path()).unwrap();
    let mut permit = Some(Arc::clone(&operations).lock_owned().await);
    let now = Instant::now();
    prepared
        .commit(&reservation, root, test_admission(), &mut permit, now)
        .unwrap();
    assert!(operations.try_lock().is_err());
    assert!(
        prepared
            .reserve(
                PreparedWorkspaceBinding::new(
                    "main",
                    2,
                    "next",
                    WorkspaceId::from_bytes([5; 16]),
                    1,
                )
                .unwrap(),
                now + Duration::from_secs(31)
            )
            .is_ok()
    );
    assert!(operations.try_lock().is_ok());
}
