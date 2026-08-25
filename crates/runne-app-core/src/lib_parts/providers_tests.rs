#[test]
fn provider_statuses_require_an_authenticated_owner_projection() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open(&directory.path().join("profile.sqlite3")).expect("open core");

    assert!(matches!(
        core.provider_statuses().expect_err("unconfigured owner"),
        AppCoreError::RuntimeUnavailable
    ));
}
