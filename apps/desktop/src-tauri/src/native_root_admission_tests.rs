use super::*;

#[tokio::test]
async fn external_lifecycle_rejects_native_root_admission() {
    let directory = tempfile::tempdir().expect("directory");
    let path = std::fs::canonicalize(directory.path()).expect("canonical root path");
    let root = VerifiedRootHandle::open(&path).expect("root");
    assert!(
        RuntimeLifecycleManager::external()
            .prepare_root_admission(root, WorkspaceId::from_bytes([4; 16]), 1)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn external_lifecycle_rejects_credential_enrollment_lease() {
    assert!(RuntimeLifecycleManager::external()
        .acquire_credential_enrollment_lease()
        .await
        .is_err());
}
