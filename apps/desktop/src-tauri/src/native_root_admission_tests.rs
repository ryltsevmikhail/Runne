use super::*;

#[tokio::test]
async fn external_lifecycle_rejects_native_root_admission() {
    let directory = tempfile::tempdir().expect("directory");
    let root = VerifiedRootHandle::open(directory.path()).expect("root");
    assert!(
        RuntimeLifecycleManager::external()
            .prepare_root_admission(root, WorkspaceId::from_bytes([4; 16]), 1)
            .await
            .is_err()
    );
}
