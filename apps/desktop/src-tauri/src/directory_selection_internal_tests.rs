
use std::time::{Duration, Instant};

use super::*;
use crate::directory_selection_test_support::test_admission;
use crate::prepared_workspace::PreparedWorkspaceRef;

fn test_root() -> (tempfile::TempDir, VerifiedRootHandle) {
    let directory = tempfile::tempdir().unwrap();
    let root = crate::directory_selection_test_support::test_root_handle(directory.path());
    (directory, root)
}

#[test]
fn page_load_issues_a_host_generation_and_rejects_stale_selection() {
    let manager = DirectorySelectionManager::new(Duration::from_secs(30)).unwrap();
    let generations = manager.renderer_generations();
    assert!(generations.current("main").is_err());
    assert_eq!(generations.page_loaded("main").unwrap(), 1);
    let (_directory, root) = test_root();
    let reference = manager
        .issue("main", 1, "request", root, Instant::now())
        .unwrap();
    assert_eq!(generations.page_loaded("main").unwrap(), 2);
    assert!(
        manager
            .consume(&reference, "main", 1, "request", Instant::now())
            .is_err()
    );
}

#[test]
fn reload_fences_pre_admission_reservation_before_commit() {
    let selections = DirectorySelectionManager::new(Duration::from_secs(30)).unwrap();
    assert_eq!(
        selections
            .renderer_generations()
            .page_loaded("main")
            .unwrap(),
        1
    );
    let prepared = selections.prepared_workspaces();
    let now = Instant::now();
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
            now,
        )
        .unwrap();
    assert_eq!(
        selections
            .renderer_generations()
            .page_loaded("main")
            .unwrap(),
        2
    );
    let (_directory, root) = test_root();
    assert!(
        prepared
            .commit(&reference, root, test_admission(), &mut None, now)
            .is_err()
    );
}

#[test]
fn prepared_response_is_redacted_and_camel_case() {
    let reference =
        serde_json::from_str::<PreparedWorkspaceRef>(&format!("\"{}\"", "a".repeat(64))).unwrap();
    assert_eq!(
        serde_json::to_value(PreparedWorkspaceResponse::new(reference)).unwrap(),
        serde_json::json!({
            "reference": "a".repeat(64),
            "summary": { "displayName": "Selected folder" },
        })
    );
}

#[test]
fn prepared_workspace_requires_exact_binding_and_is_consume_once() {
    let selections = DirectorySelectionManager::new(Duration::from_secs(30)).unwrap();
    let generations = selections.renderer_generations();
    assert_eq!(generations.page_loaded("main").unwrap(), 1);
    let prepared = selections.prepared_workspaces();
    let now = Instant::now();
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
            now,
        )
        .unwrap();
    let (_directory, root) = test_root();
    prepared
        .commit(&reference, root, test_admission(), &mut None, now)
        .unwrap();
    assert!(
        prepared
            .consume(&reference, "other", 1, "request", now)
            .is_err()
    );
    assert!(
        prepared
            .consume(&reference, "main", 2, "request", now)
            .is_err()
    );
    assert!(
        prepared
            .consume(&reference, "main", 1, "other", now)
            .is_err()
    );
    let native = prepared
        .consume(&reference, "main", 1, "request", now)
        .unwrap();
    assert_eq!(native.workspace_id(), WorkspaceId::from_bytes([4; 16]));
    assert_eq!(native.expected_version(), 1);
    drop(native.into_native_parts());
    assert!(
        prepared
            .consume(&reference, "main", 1, "request", now)
            .is_err()
    );
}

#[test]
fn destroy_and_expiry_fence_prepared_references_and_recover_capacity() {
    let selections = DirectorySelectionManager::new(Duration::from_secs(30)).unwrap();
    let generations = selections.renderer_generations();
    assert_eq!(generations.page_loaded("main").unwrap(), 1);
    let prepared = selections.prepared_workspaces();
    let now = Instant::now();
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
            now,
        )
        .unwrap();
    let (_directory, root) = test_root();
    prepared
        .commit(&reference, root, test_admission(), &mut None, now)
        .unwrap();
    assert_eq!(generations.fence_destroyed("main").unwrap(), 2);
    assert!(
        prepared
            .consume(&reference, "main", 1, "request", now)
            .is_err()
    );
    assert_eq!(generations.page_loaded("main").unwrap(), 3);
    for index in 0..64 {
        let reference = prepared
            .reserve(
                PreparedWorkspaceBinding::new(
                    "main",
                    3,
                    &format!("request-{index}"),
                    WorkspaceId::from_bytes([4; 16]),
                    1,
                )
                .unwrap(),
                now,
            )
            .unwrap();
        let (_directory, root) = test_root();
        prepared
            .commit(&reference, root, test_admission(), &mut None, now)
            .unwrap();
    }
    assert!(
        prepared
            .reserve(
                PreparedWorkspaceBinding::new(
                    "main",
                    3,
                    "full",
                    WorkspaceId::from_bytes([5; 16]),
                    1,
                )
                .unwrap(),
                now
            )
            .is_err()
    );
    assert!(
        prepared
            .reserve(
                PreparedWorkspaceBinding::new(
                    "main",
                    3,
                    "next",
                    WorkspaceId::from_bytes([5; 16]),
                    1,
                )
                .unwrap(),
                now + Duration::from_secs(31)
            )
            .is_ok()
    );
}

#[test]
fn renderer_generation_overflow_does_not_reuse_a_generation() {
    let selections = DirectorySelectionManager::new(Duration::from_secs(30)).unwrap();
    let generations = selections.renderer_generations();
    generations
        .set_generation_for_test("main", u64::MAX)
        .unwrap();
    assert!(generations.fence_reload("main").is_err());
    assert_eq!(generations.current("main").unwrap(), u64::MAX);
}
