
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::*;
use crate::directory_selection_test_support::test_admission;

#[tokio::test]
async fn idle_prepared_expiry_releases_the_operation_permit_without_followup_ipc() {
    let selections = DirectorySelectionManager::new(Duration::from_millis(20)).unwrap();
    assert_eq!(
        selections
            .renderer_generations()
            .page_loaded("main")
            .unwrap(),
        1
    );
    let prepared = selections.prepared_workspaces();
    let operations = Arc::new(tokio::sync::Mutex::new(()));
    let reference = prepared
        .reserve(
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
        .unwrap();

    let released = tokio::time::timeout(Duration::from_secs(1), operations.lock_owned()).await;
    assert!(
        released.is_ok(),
        "idle prepared lease must expire without another IPC call"
    );
}

#[tokio::test]
async fn clearing_pending_authority_releases_a_live_prepared_operation_permit() {
    let selections = DirectorySelectionManager::new(Duration::from_secs(1)).unwrap();
    assert_eq!(
        selections
            .renderer_generations()
            .page_loaded("main")
            .unwrap(),
        1
    );
    let prepared = selections.prepared_workspaces();
    let operations = Arc::new(tokio::sync::Mutex::new(()));
    let reference = prepared
        .reserve(
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
        .unwrap();
    assert!(operations.try_lock().is_err());

    selections.clear_pending_authority();
    assert!(operations.try_lock().is_ok());
}

#[tokio::test]
async fn old_expiry_tick_preserves_a_newer_consumed_then_replaced_reference() {
    let selections = DirectorySelectionManager::new(Duration::from_millis(100)).unwrap();
    assert_eq!(
        selections
            .renderer_generations()
            .page_loaded("main")
            .unwrap(),
        1
    );
    let prepared = selections.prepared_workspaces();
    let first_started = Instant::now();
    let first = prepared
        .reserve(
            PreparedWorkspaceBinding::new("main", 1, "first", WorkspaceId::from_bytes([4; 16]), 1)
                .unwrap(),
            first_started,
        )
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    prepared
        .commit(
            &first,
            crate::directory_selection_test_support::test_root_handle(directory.path()),
            test_admission(),
            &mut None,
            Instant::now(),
        )
        .unwrap();
    tokio::time::sleep(Duration::from_millis(25)).await;
    drop(
        prepared
            .consume(&first, "main", 1, "first", Instant::now())
            .unwrap(),
    );

    let second = prepared
        .reserve(
            PreparedWorkspaceBinding::new("main", 1, "second", WorkspaceId::from_bytes([5; 16]), 1)
                .unwrap(),
            Instant::now(),
        )
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    prepared
        .commit(
            &second,
            crate::directory_selection_test_support::test_root_handle(directory.path()),
            test_admission(),
            &mut None,
            Instant::now(),
        )
        .unwrap();
    let old_tick = first_started + Duration::from_millis(105);
    tokio::time::sleep(old_tick.saturating_duration_since(Instant::now())).await;
    assert!(
        prepared
            .consume(&second, "main", 1, "second", Instant::now())
            .is_ok()
    );
}
