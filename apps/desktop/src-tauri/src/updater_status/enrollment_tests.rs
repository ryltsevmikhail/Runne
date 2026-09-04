use super::*;

#[tokio::test]
async fn enrollment_preparation_rejects_without_a_compiled_updater() {
    let directory = tempfile::tempdir().unwrap();
    let store = UpdateStatusStore::new(directory.path());
    assert!(store.prepare_installed_native_enrollment().await.is_err());
}

#[tokio::test]
async fn startup_does_not_report_success_for_corrupt_installed_admission() {
    let directory = tempfile::tempdir().unwrap();
    let (coordinator, _, _) =
        runne_platform_desktop::test_only_current_enrollment_updater_fixture(directory.path())
            .into_parts();
    let mut store = UpdateStatusStore::new(directory.path());
    store.updater = Some(Arc::new(tokio::sync::Mutex::new(CompiledUpdater {
        endpoint: "https://updates.example.test",
        rollback_floor: "1.0.0",
        coordinator,
    })));
    std::fs::write(
        directory.path().join("updates/install-state.json"),
        b"corrupt",
    )
    .unwrap();
    assert!(store.prepare_installed_native_enrollment().await.is_err());
    assert!(
        crate::provider_credential_enrollment::reconcile_startup(
            &crate::RuntimeLifecycleManager::bundled_unavailable(),
            &store,
        )
        .await
        .is_err(),
        "corrupt admission must not become a successful startup skip"
    );
}

#[tokio::test]
async fn startup_without_compiled_updater_skips_without_acquiring_runtime() {
    let directory = tempfile::tempdir().unwrap();
    let store = UpdateStatusStore::new(directory.path());
    assert!(
        crate::provider_credential_enrollment::reconcile_startup(
            &crate::RuntimeLifecycleManager::bundled_unavailable(),
            &store,
        )
        .await
        .is_ok()
    );
}
