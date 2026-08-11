use super::*;

#[test]
fn zero_ttl_is_rejected_before_the_native_handle_is_retained() {
    let manager = DirectorySelectionManager::new(Duration::ZERO);
    let directory = tempfile::tempdir().unwrap();
    let root = VerifiedRootHandle::open(directory.path()).unwrap();

    assert!(manager
        .issue("main", 1, "request", root, Instant::now())
        .is_err());
}
