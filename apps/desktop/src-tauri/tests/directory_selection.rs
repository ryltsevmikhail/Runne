use std::path::Path;
use std::time::{Duration, Instant};

use gocode_desktop::{DirectorySelectionManager, RendererGenerationManager, VerifiedRootHandle};
use tempfile::tempdir;

fn root() -> (tempfile::TempDir, VerifiedRootHandle) {
    let directory = tempdir().unwrap();
    let root = VerifiedRootHandle::open(directory.path()).unwrap();
    (directory, root)
}

#[test]
fn directory_selection_is_bound_to_window_generation_request_and_single_use() {
    let (_directory, selected_root) = root();
    let manager = DirectorySelectionManager::new(Duration::from_secs(30));
    let now = Instant::now();
    let selection = manager
        .issue("main", 7, "request-1", selected_root, now)
        .unwrap();

    assert!(
        manager
            .consume(&selection, "other", 7, "request-1", now)
            .is_err()
    );
    assert!(
        manager
            .consume(&selection, "main", 6, "request-1", now)
            .is_err()
    );
    assert!(
        manager
            .consume(&selection, "main", 7, "other", now)
            .is_err()
    );
    assert!(
        manager
            .consume(&selection, "main", 7, "request-1", now)
            .is_ok()
    );
    assert!(
        manager
            .consume(&selection, "main", 7, "request-1", now)
            .is_err()
    );
}

#[test]
fn directory_selection_expires_and_window_invalidation_removes_it() {
    let (_directory, selected_root) = root();
    let manager = DirectorySelectionManager::new(Duration::from_secs(1));
    let now = Instant::now();
    let expired = manager
        .issue("main", 7, "request-1", selected_root, now)
        .unwrap();
    assert!(
        manager
            .consume(
                &expired,
                "main",
                7,
                "request-1",
                now + Duration::from_secs(1)
            )
            .is_err()
    );

    let (_directory, selected_root) = root();
    let cancelled = manager
        .issue("main", 7, "request-2", selected_root, now)
        .unwrap();
    manager.invalidate_window("main").unwrap();
    assert!(
        manager
            .consume(&cancelled, "main", 7, "request-2", now)
            .is_err()
    );
}

#[test]
fn directory_selection_references_are_random_bounded_and_redacted() {
    let (_directory, selected_root) = root();
    let manager = DirectorySelectionManager::new(Duration::from_secs(30));
    let selection = manager
        .issue("main", 7, "request-1", selected_root, Instant::now())
        .unwrap();
    let encoded = serde_json::to_string(&selection).unwrap();

    assert!(encoded.len() <= 128);
    assert_eq!(
        format!("{selection:?}"),
        "DirectorySelectionRef(<redacted>)"
    );
    assert!(!encoded.contains(Path::new("/").to_string_lossy().as_ref()));
}

#[test]
fn directory_selection_renderer_generation_never_reuses_destroyed_or_reloaded_window_generation() {
    let generations = RendererGenerationManager::new();
    let first = generations.current("main").unwrap();
    let reloaded = generations.fence_reload("main").unwrap();
    let destroyed = generations.fence_destroyed("main").unwrap();

    assert!(reloaded > first);
    assert!(destroyed > reloaded);
    assert_eq!(generations.current("main").unwrap(), destroyed);
}

#[test]
fn directory_selection_rejects_noncanonical_references_and_non_ascii_bindings() {
    assert!(serde_json::from_str::<gocode_desktop::DirectorySelectionRef>("\"A\"").is_err());
    let (_directory, selected_root) = root();
    let manager = DirectorySelectionManager::new(Duration::from_secs(1));

    assert!(
        manager
            .issue("máin", 1, "request", selected_root, Instant::now())
            .is_err()
    );

    let (_directory, selected_root) = root();
    let long_lived = DirectorySelectionManager::new(Duration::from_secs(31));
    assert!(
        long_lived
            .issue("main", 1, "request", selected_root, Instant::now())
            .is_err()
    );
}

#[test]
#[cfg(feature = "test-support")]
fn directory_selection_collision_and_poisoned_invalidation_fail_closed() {
    let manager = DirectorySelectionManager::new(Duration::from_secs(30));
    let now = Instant::now();
    let reference = "a".repeat(64);
    let (_directory, first_root) = root();
    let first = manager
        .issue_with_reference_for_test("main", 1, "one", first_root, now, reference.clone())
        .unwrap();
    let (_directory, second_root) = root();
    assert!(
        manager
            .issue_with_reference_for_test("main", 1, "two", second_root, now, reference)
            .is_err()
    );
    assert!(manager.consume(&first, "main", 1, "one", now).is_ok());

    let (_directory, selected_root) = root();
    let selection = manager
        .issue("main", 1, "three", selected_root, now)
        .unwrap();
    manager.poison_for_test();
    assert!(manager.invalidate_window("main").is_err());
    assert!(
        manager
            .consume(&selection, "main", 1, "three", now)
            .is_err()
    );
}

#[test]
#[cfg(feature = "test-support")]
fn directory_selection_generation_overflow_is_rejected_without_reuse() {
    let generations = RendererGenerationManager::new();
    generations
        .set_generation_for_test("main", u64::MAX)
        .unwrap();

    assert!(generations.fence_reload("main").is_err());
    assert_eq!(generations.current("main").unwrap(), u64::MAX);
}
