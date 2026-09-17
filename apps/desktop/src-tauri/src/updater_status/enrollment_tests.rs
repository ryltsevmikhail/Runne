use super::*;

#[tokio::test]
async fn enrollment_preparation_rejects_without_a_compiled_updater() {
    let directory = tempfile::tempdir().unwrap();
    let store = UpdateStatusStore::new(directory.path());
    assert!(store.prepare_installed_native_enrollment().await.is_err());
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
#[tokio::test]
async fn startup_does_not_report_success_for_corrupt_installed_admission() {
    let directory = tempfile::tempdir().unwrap();
    let (coordinator, _, _) =
        runne_platform_desktop::test_only_current_enrollment_updater_fixture(directory.path())
            .into_parts();
    let mut store = UpdateStatusStore::new(directory.path());
    store.updater = Some(Arc::new(tokio::sync::Mutex::new(CompiledUpdater {
        endpoint: Some("https://updates.example.test"),
        rollback_floor: Some("1.0.0"),
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

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
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

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[tokio::test]
#[allow(
    clippy::significant_drop_tightening,
    reason = "retain the updater fixture through the async admission assertion"
)]
async fn installed_admission_revalidation_does_not_require_remote_feed() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = enrollment::test_only_current_enrollment_updater(directory.path()).await;
    assert!(
        fixture
            .lease
            .revalidate_confirmed(&fixture.confirmed)
            .is_ok()
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[tokio::test]
async fn installed_only_mode_cannot_check_feed_or_install_a_committed_release() {
    let directory = tempfile::tempdir().unwrap();
    let (coordinator, _, _) =
        runne_platform_desktop::test_only_current_enrollment_updater_fixture(directory.path())
            .into_parts();
    let mut store = UpdateStatusStore::new(directory.path());
    store.updater = Some(Arc::new(tokio::sync::Mutex::new(CompiledUpdater {
        endpoint: None,
        rollback_floor: None,
        coordinator,
    })));
    assert!(store.check_update().await.is_err());
    assert!(store.prepare_update_install(0, false).is_err());
}
