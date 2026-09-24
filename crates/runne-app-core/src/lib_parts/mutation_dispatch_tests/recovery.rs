#[tokio::test]
async fn prepared_mutation_is_rejected_while_resync_is_required() {
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        mutation_test_client("authority-a", "lineage-a", 1),
    )
    .expect("core");
    let lease = core
        .prepare_mutation(
            MutationRequest::create_conversation(CanonicalId::now_v7(), CanonicalId::now_v7())
                .expect("request"),
        )
        .await
        .expect("prepare");
    core.set_resync_required_for_scope(ReplayScopeKey {
        runtime_authority: "authority-a".into(),
        principal: "principal".into(),
        lineage: "lineage-a".into(),
        scope: "conversation:test".into(),
        binding_digest: "11".repeat(32),
    })
    .expect("resync");
    assert!(matches!(
        core.dispatch_prepared_mutation(lease).await,
        Err(AppCoreError::RuntimeUnavailable)
    ));
}

#[tokio::test]
async fn pending_resync_keeps_the_bundled_lifecycle_degraded_after_restart() {
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_runtime_mode(
        &directory.path().join("profile.sqlite3"),
        RuntimeMode::Bundled,
    )
    .expect("core");
    let first = core.begin_bundled_runtime_start().await.expect("start");
    core.install_bundled_runtime_client(
        first,
        runne_runtime_client::mock_protected_authenticated_runtime_client(
            "http://127.0.0.1:1",
            mutation_test_client("authority-a", "lineage-a", 1)
                .session_info()
                .clone(),
        )
        .expect("client"),
    )
    .await
    .expect("install");
    core.set_resync_required_for_scope(ReplayScopeKey {
        runtime_authority: "authority-a".into(),
        principal: "principal".into(),
        lineage: "lineage-a".into(),
        scope: "conversation:test".into(),
        binding_digest: "11".repeat(32),
    })
    .expect("resync");
    let next = core.begin_bundled_runtime_restart().await.expect("restart");
    core.install_bundled_runtime_client(
        next,
        runne_runtime_client::mock_protected_authenticated_runtime_client(
            "http://127.0.0.1:2",
            mutation_test_client("authority-a", "lineage-a", 2)
                .session_info()
                .clone(),
        )
        .expect("client"),
    )
    .await
    .expect("install");
    assert_eq!(
        core.bootstrap().expect("bootstrap").runtime_lifecycle,
        RuntimeLifecycleStatus::Degraded
    );
}
