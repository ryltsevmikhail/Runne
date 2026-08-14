fn mutation_test_client(
    authority: &str,
    lineage: &str,
    generation: u64,
) -> AuthenticatedRuntimeClient {
    gocode_runtime_client::mock_authenticated_runtime_client(
        "http://127.0.0.1:1",
        gocode_runtime_client::RuntimeSessionInfo {
            profile_id: "gocode-ui-client/2".into(),
            schema_hash: gocode_runtime_client::GOLDEN_BUNDLE_HASH.into(),
            runtime_version: "test".into(),
            capabilities: gocode_runtime_client::REQUIRED_RUNTIME_CAPABILITIES
                .iter()
                .map(ToString::to_string)
                .collect(),
            authority_id: authority.into(),
            principal_id: "principal".into(),
            event_log_lineage_id: lineage.into(),
            daemon_instance_id: "daemon-instance".into(),
            launch_generation: generation,
            session_id: format!("session-{generation}"),
            authorization_epoch: 1,
            sensitivity_ceiling: "sensitive".into(),
            certificate_sha256: "11".repeat(32),
            capability_digest: "22".repeat(32),
        },
    )
    .expect("mock client")
}

#[tokio::test]
async fn prepared_mutation_is_rejected_after_runtime_exit_from_live() {
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        mutation_test_client("authority-a", "lineage-a", 1),
    )
    .expect("core");
    let lease = core.prepare_mutation(MutationRequest::create_conversation(CanonicalId::now_v7(), CanonicalId::now_v7()).expect("request")).await.expect("prepare");
    core.set_runtime_failure(RuntimeAvailability::Reconnecting).expect("fence");
    assert!(matches!(core.dispatch_prepared_mutation(lease).await, Err(AppCoreError::RuntimeUnavailable)));
}

#[tokio::test]
async fn failed_catch_up_after_reconciling_fences_the_prior_operation_context() {
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        mutation_test_client("authority-a", "lineage-a", 1),
    )
    .expect("core");
    let context = core.live_runtime_operation_context().expect("live context");

    core.transition_runtime(RuntimeAvailability::Reconciling)
        .expect("begin catch-up");
    core.set_runtime_failure(RuntimeAvailability::Reconnecting)
        .expect("catch-up failure");

    assert!(matches!(
        core.require_current_operation_context(&context),
        Err(AppCoreError::RuntimeUnavailable)
    ));
}

#[test]
fn operation_context_rejects_every_authenticated_identity_field() {
    type Change = fn(&mut gocode_runtime_client::RuntimeSessionInfo);
    let changes: &[Change] = &[
        |value| value.session_id.push_str("-changed"),
        |value| value.daemon_instance_id.push_str("-changed"),
        |value| value.launch_generation += 1,
        |value| value.authorization_epoch += 1,
        |value| value.certificate_sha256 = "33".repeat(32),
        |value| value.authority_id.push_str("-changed"),
        |value| value.principal_id.push_str("-changed"),
        |value| value.event_log_lineage_id.push_str("-changed"),
        |value| value.profile_id.push_str("-changed"),
        |value| value.schema_hash = "44".repeat(32),
        |value| value.capability_digest = "55".repeat(32),
    ];
    for change in changes {
        let directory = tempfile::tempdir().expect("directory");
        let core = AppCore::open_with_mock_runtime(
            &directory.path().join("profile.sqlite3"),
            mutation_test_client("authority-a", "lineage-a", 1),
        )
        .expect("core");
        let context = core.live_runtime_operation_context().expect("context");
        let mut session = core
            .runtime_client()
            .expect("client state")
            .expect("client")
            .session_info()
            .clone();
        change(&mut session);
        *core.runtime_client.write().expect("client state") = Some(
            gocode_runtime_client::mock_authenticated_runtime_client("http://127.0.0.1:1", session)
                .expect("changed client"),
        );
        assert!(matches!(
            core.require_current_operation_context(&context),
            Err(AppCoreError::RuntimeUnavailable)
        ));
    }
}

#[tokio::test]
async fn every_non_live_state_rejects_a_prepared_mutation() {
    for state in RuntimeAvailability::ALL {
        if state == RuntimeAvailability::Live {
            continue;
        }
        let directory = tempfile::tempdir().expect("directory");
        let core = AppCore::open_with_mock_runtime(
            &directory.path().join("profile.sqlite3"),
            mutation_test_client("authority-a", "lineage-a", 1),
        )
        .expect("core");
        let lease = core.prepare_mutation(MutationRequest::create_conversation(CanonicalId::now_v7(), CanonicalId::now_v7()).expect("request")).await.expect("prepare");
        core.set_runtime_availability(state).expect("state");
        assert!(matches!(core.dispatch_prepared_mutation(lease).await, Err(AppCoreError::RuntimeUnavailable)), "{state:?}");
    }
}

#[tokio::test]
async fn prepared_mutation_is_rejected_after_client_replacement_or_identity_change() {
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        mutation_test_client("authority-a", "lineage-a", 1),
    )
    .expect("core");
    let replaced = core.prepare_mutation(MutationRequest::create_conversation(CanonicalId::now_v7(), CanonicalId::now_v7()).expect("request")).await.expect("prepare");
    core.replace_runtime_client(Some(mutation_test_client("authority-a", "lineage-a", 2))).expect("replace");
    assert!(matches!(core.dispatch_prepared_mutation(replaced).await, Err(AppCoreError::RuntimeUnavailable)));

    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        mutation_test_client("authority-a", "lineage-a", 1),
    )
    .expect("core");
    let changed = core.prepare_mutation(MutationRequest::create_conversation(CanonicalId::now_v7(), CanonicalId::now_v7()).expect("request")).await.expect("prepare");
    core.replace_runtime_client(Some(mutation_test_client("authority-b", "lineage-b", 3))).expect("replace");
    assert!(matches!(core.dispatch_prepared_mutation(changed).await, Err(AppCoreError::RuntimeUnavailable)));
}

#[test]
fn durable_mutation_binding_excludes_ephemeral_session_fields() {
    let first = replay::StableRuntimeIdentity {
        authority: "authority".into(), principal: "principal".into(), lineage: "lineage".into(),
        profile_id: "profile".into(), schema_hash: "schema".into(), capability_digest: "caps".into(),
        binding_digest: "binding".into(), launch_generation: 1, session_id: "session-1".into(),
        daemon_instance_id: "daemon-1".into(), authorization_epoch: 1, certificate_sha256: "cert-1".into(),
    };
    let mut rotated = first.clone();
    rotated.launch_generation = 2;
    rotated.session_id = "session-2".into();
    rotated.daemon_instance_id = "daemon-2".into();
    rotated.authorization_epoch = 2;
    rotated.certificate_sha256 = "cert-2".into();
    assert!(first.same_durable_runtime(&rotated));
    assert_eq!(digest_runtime_identity(&first), digest_runtime_identity(&rotated));
    for mutate in [
        |value: &mut replay::StableRuntimeIdentity| value.authority = "changed".into(),
        |value: &mut replay::StableRuntimeIdentity| value.lineage = "changed".into(),
        |value: &mut replay::StableRuntimeIdentity| value.profile_id = "changed".into(),
        |value: &mut replay::StableRuntimeIdentity| value.schema_hash = "changed".into(),
        |value: &mut replay::StableRuntimeIdentity| value.capability_digest = "changed".into(),
    ] {
        let mut changed = first.clone();
        mutate(&mut changed);
        assert!(!first.same_durable_runtime(&changed));
        assert_ne!(digest_runtime_identity(&first), digest_runtime_identity(&changed));
    }
}

#[tokio::test]
async fn prepared_mutation_is_rejected_while_resync_is_required() {
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        mutation_test_client("authority-a", "lineage-a", 1),
    )
    .expect("core");
    let lease = core.prepare_mutation(MutationRequest::create_conversation(CanonicalId::now_v7(), CanonicalId::now_v7()).expect("request")).await.expect("prepare");
    core.set_resync_required_for_scope(ReplayScopeKey {
        runtime_authority: "authority-a".into(), principal: "principal".into(), lineage: "lineage-a".into(), scope: "conversation:test".into(), binding_digest: "11".repeat(32),
    }).expect("resync");
    assert!(matches!(core.dispatch_prepared_mutation(lease).await, Err(AppCoreError::RuntimeUnavailable)));
}

#[tokio::test]
async fn pending_resync_keeps_the_bundled_lifecycle_degraded_after_restart() {
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_runtime_mode(&directory.path().join("profile.sqlite3"), RuntimeMode::Bundled).expect("core");
    let first = core.begin_bundled_runtime_start().await.expect("start");
    core.install_bundled_runtime_client(first, gocode_runtime_client::mock_protected_authenticated_runtime_client("http://127.0.0.1:1", mutation_test_client("authority-a", "lineage-a", 1).session_info().clone()).expect("client")).await.expect("install");
    core.set_resync_required_for_scope(ReplayScopeKey { runtime_authority: "authority-a".into(), principal: "principal".into(), lineage: "lineage-a".into(), scope: "conversation:test".into(), binding_digest: "11".repeat(32) }).expect("resync");
    let next = core.begin_bundled_runtime_restart().await.expect("restart");
    core.install_bundled_runtime_client(next, gocode_runtime_client::mock_protected_authenticated_runtime_client("http://127.0.0.1:2", mutation_test_client("authority-a", "lineage-a", 2).session_info().clone()).expect("client")).await.expect("install");
    assert_eq!(core.bootstrap().expect("bootstrap").runtime_lifecycle, RuntimeLifecycleStatus::Degraded);
}
