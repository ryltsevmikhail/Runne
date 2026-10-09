use super::*;
use crate::permissions_tests::{COMMAND, MemoryIndex, intent, saved_record, session_info};
use crate::permissions_transport_tests::RecoveryFakeRuntime as FakeRuntime;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

#[test]
fn immutable_record_roundtrips_and_binds_all_request_fields() {
    let input = intent();
    let record = decode_recovery_record(&saved_record(&input)).unwrap();
    assert_eq!(record.command_id, input.command_id);
    assert_eq!(record.scope_digest, scope_digest(&record.stable_runtime));
    assert_eq!(
        record.intent_digest,
        local_intent_digest(&input, &record.stable_runtime)
    );
    let mut changed = input.clone();
    changed.idempotency_key.push('x');
    assert_ne!(
        local_intent_digest(&input, &record.stable_runtime),
        local_intent_digest(&changed, &record.stable_runtime)
    );
    changed = input.clone();
    changed.expected_authorization_revision += 1;
    assert_ne!(
        local_intent_digest(&input, &record.stable_runtime),
        local_intent_digest(&changed, &record.stable_runtime)
    );
    changed = input.clone();
    changed.expires_at_unix_ms = Some(1_800_000_000_000);
    assert_ne!(
        local_intent_digest(&input, &record.stable_runtime),
        local_intent_digest(&changed, &record.stable_runtime)
    );
}

#[test]
fn epoch_zero_mode_record_roundtrips_and_zero_generation_stays_corrupt() {
    let input = intent();
    let mut session = session_info();
    session.authorization_epoch = 0;
    let bytes = make_recovery_record(
        &input,
        StableRuntimeIdentity::from_session(&session).unwrap(),
        RuntimeAuditSnapshot::from_session(&session).unwrap(),
    )
    .unwrap();
    assert_eq!(
        decode_recovery_record(&bytes).unwrap().audit.authorization_epoch,
        0
    );

    let mut generation_zero = session;
    generation_zero.launch_generation = 0;
    assert!(RuntimeAuditSnapshot::from_session(&generation_zero).is_err());

    let mut malformed: serde_json::Value =
        serde_json::from_slice(&saved_record(&input)).unwrap();
    malformed["audit"]["launchGeneration"] = serde_json::json!(0);
    assert!(matches!(
        decode_recovery_record(&serde_json::to_vec(&malformed).unwrap()),
        Err(RecoveryError::Corrupt)
    ));
}

#[test]
fn authority_id_uses_exact_lowercase_32_character_hex_identity() {
    let valid = session_info();
    let stable = StableRuntimeIdentity::from_session(&valid).unwrap();
    assert_eq!(stable.authority_id, valid.authority_id);
    for invalid in [
        "018f2e3a-7000-7000-8000-000000000003",
        "018F2E3A700070008000000000000003",
        "018f2e3a70007000800000000000000g",
        "018f2e3a70007000800000000000003",
        "018f2e3a7000700080000000000000030",
    ] {
        let mut session = valid.clone();
        session.authority_id = invalid.to_owned();
        assert!(StableRuntimeIdentity::from_session(&session).is_err());
    }
}

#[tokio::test]
async fn distinct_valid_authorities_have_distinct_scopes_and_recovery_stops_before_reads() {
    let input = intent();
    let first = session_info();
    let mut second = first.clone();
    second.authority_id = "018f2e3a700070008000000000000004".to_owned();
    let first_stable = StableRuntimeIdentity::from_session(&first).unwrap();
    let second_stable = StableRuntimeIdentity::from_session(&second).unwrap();
    assert_ne!(scope_digest(&first_stable), scope_digest(&second_stable));
    let record = make_recovery_record(
        &input,
        second_stable,
        RuntimeAuditSnapshot::from_session(&second).unwrap(),
    )
    .unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let runtime = FakeRuntime {
        info: first,
        ..FakeRuntime::new(input.command_id, events.clone())
    };
    let index = MemoryIndex {
        events: events.clone(),
        ..MemoryIndex::default()
    };
    index.records.lock().unwrap().push((
        scope_digest(&first_stable),
        COMMAND.to_owned(),
        record,
    ));

    assert!(matches!(
        execute_mode_set_with_index(&runtime, input, &index).await,
        Err(CliError::PermissionRecoveryScopeMismatch(id)) if id.to_string() == COMMAND
    ));
    assert_eq!(runtime.status_gets.load(Ordering::Relaxed), 0);
    assert_eq!(runtime.posts.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn durable_creation_posts_once_and_later_invocation_only_reads() {
    let input = intent();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut runtime = FakeRuntime::new(input.command_id, events.clone());
    runtime.info.authorization_epoch = 0;
    let index = MemoryIndex {
        events: events.clone(),
        ..MemoryIndex::default()
    };
    assert!(
        execute_mode_set_with_index(&runtime, input.clone(), &index)
            .await
            .is_ok()
    );
    assert_eq!(
        events.lock().unwrap().as_slice(),
        &["status_get", "record_durable", "post"]
    );
    events.lock().unwrap().clear();
    assert!(
        execute_mode_set_with_index(&runtime, input, &index)
            .await
            .is_ok()
    );
    assert_eq!(runtime.posts.load(Ordering::Relaxed), 1);
    assert_eq!(runtime.command_gets.load(Ordering::Relaxed), 1);
    assert_eq!(
        events.lock().unwrap().as_slice(),
        &["status_get", "command_get"]
    );
}

#[tokio::test]
async fn unknown_post_is_reconciled_by_same_id_get_without_retry() {
    let input = intent();
    let events = Arc::new(Mutex::new(Vec::new()));
    let runtime = FakeRuntime::new(input.command_id, events.clone());
    runtime.unknown_after_post.store(true, Ordering::Relaxed);
    let index = MemoryIndex {
        events: events.clone(),
        ..MemoryIndex::default()
    };
    assert!(
        execute_mode_set_with_index(&runtime, input, &index)
            .await
            .is_ok()
    );
    assert_eq!(runtime.posts.load(Ordering::Relaxed), 1);
    assert_eq!(runtime.command_gets.load(Ordering::Relaxed), 1);
    assert_eq!(
        events.lock().unwrap().as_slice(),
        &["status_get", "record_durable", "post", "command_get"]
    );
}

#[tokio::test]
async fn mismatched_existing_intent_fails_before_runtime_reads_or_post() {
    let input = intent();
    let events = Arc::new(Mutex::new(Vec::new()));
    let runtime = FakeRuntime::new(input.command_id, events.clone());
    let index = MemoryIndex {
        events: events.clone(),
        ..MemoryIndex::default()
    };
    index.records.lock().unwrap().push((
        scope_digest(&StableRuntimeIdentity::from_session(&runtime.info).unwrap()),
        COMMAND.to_owned(),
        saved_record(&input),
    ));
    let mut changed = input;
    changed.idempotency_key = "different-key".to_owned();
    assert!(
        matches!(execute_mode_set_with_index(&runtime, changed, &index).await, Err(CliError::PermissionRecoveryConflict(id)) if id.to_string() == COMMAND)
    );
    assert_eq!(runtime.status_gets.load(Ordering::Relaxed), 0);
    assert_eq!(runtime.posts.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn corrupt_or_unavailable_record_paths_never_post() {
    let input = intent();
    let events = Arc::new(Mutex::new(Vec::new()));
    let runtime = FakeRuntime::new(input.command_id, events.clone());
    let index = MemoryIndex {
        events: events.clone(),
        ..MemoryIndex::default()
    };
    index
        .records
        .lock()
        .unwrap()
        .push(("11".repeat(32), COMMAND.to_owned(), b"{".to_vec()));
    assert!(matches!(
        execute_mode_set_with_index(&runtime, input.clone(), &index).await,
        Err(CliError::PermissionRecoveryCorrupt(_))
    ));
    assert_eq!(runtime.status_gets.load(Ordering::Relaxed), 0);
    index.records.lock().unwrap().clear();
    index.fail_create.store(true, Ordering::Relaxed);
    assert!(matches!(
        execute_mode_set_with_index(&runtime, input, &index).await,
        Err(CliError::PermissionRecoveryIo(_))
    ));
    assert_eq!(runtime.status_gets.load(Ordering::Relaxed), 1);
    assert_eq!(runtime.posts.load(Ordering::Relaxed), 0);
}

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

        assert!(execute_mode_set_with_index(&runtime, input.clone(), &index)
            .await
            .is_ok());
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
