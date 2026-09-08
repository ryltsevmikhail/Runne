use super::*;

#[test]
fn zero_ttl_is_rejected_before_the_native_handle_is_retained() {
    assert!(DirectorySelectionManager::new(Duration::ZERO).is_err());
}

#[cfg(feature = "test-support")]
#[test]
fn a_reference_collision_does_not_replace_the_original_handle() {
    let manager = DirectorySelectionManager::new(Duration::from_secs(1)).unwrap();
    assert_eq!(manager.renderer_generations().page_loaded("main").unwrap(), 1);
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let now = Instant::now();
    let reference = "a".repeat(64);
    let original = manager
        .issue_with_reference_for_test(
            "main",
            1,
            "request",
            crate::directory_selection_test_support::test_root_handle(first.path()),
            now,
            reference.clone(),
        )
        .unwrap();
    assert!(manager
        .issue_with_reference_for_test(
            "main",
            1,
            "request-2",
            crate::directory_selection_test_support::test_root_handle(second.path()),
            now,
            reference,
        )
        .is_err());
    assert!(manager.consume(&original, "main", 1, "request", now).is_ok());
}

#[cfg(feature = "test-support")]
#[test]
fn poisoned_invalidation_fails_closed() {
    let manager = DirectorySelectionManager::new(Duration::from_secs(1)).unwrap();
    manager.poison_for_test();
    assert!(manager.invalidate_window("main").is_err());
}
