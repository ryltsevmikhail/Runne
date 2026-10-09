use super::*;

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
    index
        .records
        .lock()
        .unwrap()
        .push((scope_digest(&first_stable), COMMAND.to_owned(), record));

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
