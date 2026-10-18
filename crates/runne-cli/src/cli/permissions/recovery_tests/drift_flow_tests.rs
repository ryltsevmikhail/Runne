use super::*;

#[tokio::test]
async fn stable_runtime_mismatch_stops_before_status_or_command_get() {
    let input = intent();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut changed_info = session_info();
    changed_info.principal_id = "principal:other-user".to_owned();
    let runtime = FakeRuntime {
        info: changed_info,
        ..FakeRuntime::new(input.command_id, events.clone())
    };
    let index = MemoryIndex {
        events: events.clone(),
        ..MemoryIndex::default()
    };
    index.records.lock().unwrap().push((
        "old-scope".to_owned(),
        COMMAND.to_owned(),
        saved_record(&input),
    ));
    assert!(
        matches!(execute_mode_set_with_index(&runtime, input, &index).await, Err(CliError::PermissionRecoveryScopeMismatch(id)) if id.to_string() == COMMAND)
    );
    assert_eq!(runtime.status_gets.load(Ordering::Relaxed), 0);
    assert_eq!(runtime.command_gets.load(Ordering::Relaxed), 0);
    assert_eq!(runtime.posts.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn unavailable_contract_get_stops_before_record_creation() {
    let input = intent();
    let events = Arc::new(Mutex::new(Vec::new()));
    let runtime = FakeRuntime::new(input.command_id, events.clone());
    runtime.status_unavailable.store(true, Ordering::Relaxed);
    let index = MemoryIndex {
        events: events.clone(),
        ..MemoryIndex::default()
    };
    assert!(matches!(
        execute_mode_set_with_index(&runtime, input, &index).await,
        Err(CliError::PermissionCommandUnavailable(_))
    ));
    assert!(index.records.lock().unwrap().is_empty());
    assert_eq!(runtime.posts.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn not_recorded_existing_intent_stays_unknown_without_post() {
    let input = intent();
    let events = Arc::new(Mutex::new(Vec::new()));
    let runtime = FakeRuntime::new(input.command_id, events.clone());
    runtime.command_missing.store(true, Ordering::Relaxed);
    let index = MemoryIndex {
        events: events.clone(),
        ..MemoryIndex::default()
    };
    index.records.lock().unwrap().push((
        scope_digest(&StableRuntimeIdentity::from_session(&runtime.info).unwrap()),
        COMMAND.to_owned(),
        saved_record(&input),
    ));
    assert!(
        matches!(execute_mode_set_with_index(&runtime, input, &index).await, Err(CliError::PermissionCommandUnknown(id)) if id.to_string() == COMMAND)
    );
    assert_eq!(runtime.status_gets.load(Ordering::Relaxed), 1);
    assert_eq!(runtime.command_gets.load(Ordering::Relaxed), 1);
    assert_eq!(runtime.posts.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn volatile_session_drift_allows_get_only_recovery() {
    let input = intent();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut changed = session_info();
    changed.daemon_instance_id = "018f2e3a-7000-7000-8000-000000000006".to_owned();
    changed.launch_generation = 2;
    changed.session_id = "55".repeat(16);
    changed.authorization_epoch = 2;
    changed.certificate_sha256 = "66".repeat(32);
    changed.capabilities = vec!["workspace.list.v1".to_owned()];
    changed.capability_digest =
        "015523519af34e64325a09f631d997aedbf1af6ea8bd842efcde4f16c9d0abcc".to_owned();
    let runtime = FakeRuntime {
        info: changed,
        ..FakeRuntime::new(input.command_id, events.clone())
    };
    let index = MemoryIndex {
        events: events.clone(),
        ..MemoryIndex::default()
    };
    index.records.lock().unwrap().push((
        scope_digest(&StableRuntimeIdentity::from_session(&session_info()).unwrap()),
        COMMAND.to_owned(),
        saved_record(&input),
    ));
    assert!(
        execute_mode_set_with_index(&runtime, input, &index)
            .await
            .is_ok()
    );
    assert_eq!(runtime.status_gets.load(Ordering::Relaxed), 1);
    assert_eq!(runtime.command_gets.load(Ordering::Relaxed), 1);
    assert_eq!(runtime.posts.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn epoch_zero_record_recovers_get_only_after_epoch_advances() {
    let input = intent();
    let mut saved_session = session_info();
    saved_session.authorization_epoch = 0;
    let saved = make_recovery_record(
        &input,
        StableRuntimeIdentity::from_session(&saved_session).unwrap(),
        RuntimeAuditSnapshot::from_session(&saved_session).unwrap(),
    )
    .unwrap();

    for authorization_epoch in [1, 2] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut current_session = session_info();
        current_session.authorization_epoch = authorization_epoch;
        let runtime = FakeRuntime {
            info: current_session,
            ..FakeRuntime::new(input.command_id, events.clone())
        };
        let index = MemoryIndex {
            events: events.clone(),
            ..MemoryIndex::default()
        };
        index.records.lock().unwrap().push((
            scope_digest(&StableRuntimeIdentity::from_session(&saved_session).unwrap()),
            COMMAND.to_owned(),
            saved.clone(),
        ));

        assert!(
            execute_mode_set_with_index(&runtime, input.clone(), &index)
                .await
                .is_ok()
        );
        assert_eq!(runtime.status_gets.load(Ordering::Relaxed), 1);
        assert_eq!(runtime.command_gets.load(Ordering::Relaxed), 1);
        assert_eq!(runtime.posts.load(Ordering::Relaxed), 0);
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &["status_get", "command_get"]
        );
    }
}

#[test]
fn recovered_receipt_must_match_saved_change_semantics() {
    let input = intent();
    let command_bytes = canonical_id_bytes(input.command_id).unwrap();
    let status: PermissionModeCommandStatusV2 = serde_json::from_value(serde_json::json!({
        "state": "committed",
        "receipt": {
            "commandId": command_bytes,
            "idempotencyKey": input.idempotency_key,
            "intentDigest": vec![1_u8; 32],
            "authorizationRevision": 10,
            "selectedMode": "full_access",
            "history": {
                "selectedMode": "full_access",
                "effective": { "state": "notReady", "reason": "preset_unavailable" },
                "authorizationRevision": 10,
                "presetVersion": 1,
                "managedPolicyVersion": 1,
                "containment": null,
                "networkState": "unavailable",
                "expiresAtUnixMs": 123
            }
        }
    }))
    .unwrap();
    assert!(
        matches!(render_validated_mode_status(status, &input), Err(CliError::PermissionCommandUnknown(id)) if id == input.command_id)
    );
}
