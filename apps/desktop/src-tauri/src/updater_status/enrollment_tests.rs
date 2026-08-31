use super::*;

#[tokio::test]
async fn enrollment_preparation_rejects_without_a_compiled_updater() {
    let directory = tempfile::tempdir().unwrap();
    let store = UpdateStatusStore::new(directory.path());
    assert!(store.prepare_installed_native_enrollment().await.is_err());
}
