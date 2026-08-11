use super::*;

#[test]
fn zero_ttl_is_rejected_before_the_native_handle_is_retained() {
    assert!(DirectorySelectionManager::new(Duration::ZERO).is_err());
}

#[cfg(feature = "test-support")]
#[test]
fn a_reference_collision_does_not_replace_the_original_handle() {
    let manager = DirectorySelectionManager::new(Duration::from_secs(1)).unwrap();
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let now = Instant::now();
    let reference = "a".repeat(64);
    let original = manager
        .issue_with_reference_for_test(
            "main",
            0,
            "request",
            VerifiedRootHandle::open(first.path()).unwrap(),
            now,
            reference.clone(),
        )
        .unwrap();
    assert!(manager
        .issue_with_reference_for_test(
            "main",
            0,
            "request-2",
            VerifiedRootHandle::open(second.path()).unwrap(),
            now,
            reference,
        )
        .is_err());
    assert!(manager.consume(&original, "main", 0, "request", now).is_ok());
}

#[cfg(feature = "test-support")]
#[test]
fn poisoned_invalidation_fails_closed() {
    let manager = DirectorySelectionManager::new(Duration::from_secs(1)).unwrap();
    manager.poison_for_test();
    assert!(manager.invalidate_window("main").is_err());
}
