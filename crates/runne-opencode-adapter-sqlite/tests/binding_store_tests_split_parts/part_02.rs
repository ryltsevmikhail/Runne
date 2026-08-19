#[test]
fn command_id_collision_is_a_typed_conflict_without_second_row() {
    let path = db_path();
    let store = SqliteSessionBindingStore::open(&path).unwrap();
    let first = key();
    let second = another_key(2);
    let value = context();
    assert_eq!(
        store.ensure_pending(&first, &value),
        Ok(EnsurePendingResult::Created)
    );
    let before = full_row(&path);
    let state_before = singleton(&path);
    assert_eq!(
        store.ensure_pending(&second, &value),
        Err(BindingError::Conflict(second))
    );
    assert_eq!(rows(&path), 1);
    assert_eq!(full_row(&path), before);
    assert_eq!(singleton(&path), state_before);
}

#[test]
fn fingerprint_only_retry_conflict_preserves_full_durable_state() {
    let path = db_path();
    let store = SqliteSessionBindingStore::open(&path).unwrap();
    let key = key();
    let value = context();
    store.ensure_pending(&key, &value).unwrap();
    let before = full_row(&path);
    let state_before = singleton(&path);
    let mut conflicting = value;
    conflicting.request_fingerprint = SessionCreateFingerprint::from_bytes([8; 32]);
    assert_eq!(
        store.ensure_pending(&key, &conflicting),
        Err(BindingError::Conflict(key))
    );
    assert_eq!(full_row(&path), before);
    assert_eq!(singleton(&path), state_before);
}

#[test]
fn indexed_context_corruption_fails_closed_for_lookup_and_retry() {
    for (column, value) in [
        ("conversation_id", "X'018f2e3a700070008000000000000004'"),
        ("workspace_id", "X'018f2e3a700070008000000000000005'"),
        ("command_id", "X'018f2e3a700070008000000000000006'"),
        ("idempotency_key", "X'726571756573742d62'"),
        (
            "request_fingerprint",
            "X'0808080808080808080808080808080808080808080808080808080808080808'",
        ),
    ] {
        let path = db_path();
        let store = SqliteSessionBindingStore::open(&path).unwrap();
        let key = key();
        let value_context = context();
        store.ensure_pending(&key, &value_context).unwrap();
        raw(&path)
            .execute(
                &format!("UPDATE session_bindings SET {column} = {value}"),
                [],
            )
            .unwrap();
        let before = full_row(&path);
        let state_before = singleton(&path);
        assert_eq!(store.lookup(&key), Err(BindingError::SerializationFailed));
        assert_eq!(
            store.ensure_pending(&key, &value_context),
            Err(BindingError::SerializationFailed)
        );
        assert_eq!(
            store.commit(&key, value_context.conversation_id, &response()),
            Err(BindingError::SerializationFailed)
        );
        assert_eq!(full_row(&path), before, "{column}");
        assert_eq!(singleton(&path), state_before, "{column}");
    }
}

#[test]
fn malformed_context_snapshot_and_codec_version_fail_closed() {
    for (column, value) in [
        ("context_codec_version", "2"),
        ("context_snapshot", "X'00'"),
    ] {
        let path = db_path();
        let store = SqliteSessionBindingStore::open(&path).unwrap();
        let key = key();
        let value_context = context();
        store.ensure_pending(&key, &value_context).unwrap();
        raw(&path)
            .execute(
                &format!("UPDATE session_bindings SET {column} = {value}"),
                [],
            )
            .unwrap();
        assert_eq!(store.lookup(&key), Err(BindingError::SerializationFailed));
        assert_eq!(
            store.ensure_pending(&key, &value_context),
            Err(BindingError::SerializationFailed)
        );
        assert_eq!(rows(&path), 1);
    }
}

fn encoded_string_offset(snapshot: &[u8], index: usize) -> usize {
    let mut at = 0;
    for _ in 0..index {
        let length = u32::from_be_bytes(snapshot[at..at + 4].try_into().unwrap()) as usize;
        at += 4 + length;
    }
    at + 4
}

fn context_identity_offset(snapshot: &[u8], field: &str) -> usize {
    let mut at = encoded_string_offset(snapshot, 3);
    let idempotency = at;
    at += u32::from_be_bytes(snapshot[at - 4..at].try_into().unwrap()) as usize;
    at += 32;
    if snapshot[at] == 1 {
        at += 1;
        let title_length = u32::from_be_bytes(snapshot[at..at + 4].try_into().unwrap()) as usize;
        at += 4 + title_length;
    } else {
        at += 1;
    }
    let principal = at + 4;
    let principal_length = u32::from_be_bytes(snapshot[at..at + 4].try_into().unwrap()) as usize;
    at += 4 + principal_length;
    let actor = at + 4;
    match field {
        "idempotency" => idempotency,
        "principal" => principal,
        "actor" => actor,
        _ => unreachable!(),
    }
}

#[test]
fn invalid_utf8_in_context_identity_fields_fails_closed_without_mutation() {
    // Strings 3, 5, and 6 are idempotency key, principal, and actor respectively.
    for field in ["idempotency", "principal", "actor"] {
        let path = db_path();
        let store = SqliteSessionBindingStore::open(&path).unwrap();
        let key = key();
        let value = context();
        store.ensure_pending(&key, &value).unwrap();
        let mut snapshot: Vec<u8> = raw(&path)
            .query_row("SELECT context_snapshot FROM session_bindings", [], |row| {
                row.get(0)
            })
            .unwrap();
        let offset = context_identity_offset(&snapshot, field);
        snapshot[offset] = 0xff;
        raw(&path)
            .execute(
                "UPDATE session_bindings SET context_snapshot = ?1",
                [snapshot],
            )
            .unwrap();
        let before = full_row(&path);
        let state_before = singleton(&path);
        assert_eq!(
            store.lookup(&key),
            Err(BindingError::SerializationFailed),
            "{field}"
        );
        assert_eq!(
            store.ensure_pending(&key, &value),
            Err(BindingError::SerializationFailed),
            "{field}"
        );
        assert_eq!(full_row(&path), before, "{field}");
        assert_eq!(singleton(&path), state_before, "{field}");
    }
}

#[test]
fn unchecked_non_v7_context_is_rejected_before_insert() {
    for field in ["conversation_id", "workspace_id", "command_id"] {
        let path = db_path();
        let store = SqliteSessionBindingStore::open(&path).unwrap();
        let mut value = context();
        match field {
            "conversation_id" => value.conversation_id = ConversationId::from_bytes([0; 16]),
            "workspace_id" => value.workspace_id = WorkspaceId::from_bytes([0; 16]),
            "command_id" => value.command_id = CommandId::from_bytes([0; 16]),
            _ => unreachable!(),
        }
        assert_eq!(
            store.ensure_pending(&key(), &value),
            Err(BindingError::SerializationFailed),
            "{field}"
        );
        assert_eq!(rows(&path), 0, "{field}");
        assert_eq!(singleton(&path), 0, "{field}");
    }
}

#[test]
fn commit_missing_conflicting_and_corrupt_response_are_non_mutating() {
    let path = db_path();
    let store = SqliteSessionBindingStore::open(&path).unwrap();
    let key = key();
    let value = context();
    assert_eq!(
        store.commit(&key, value.conversation_id, &response()),
        Err(BindingError::NotFound(key.clone()))
    );
    store.ensure_pending(&key, &value).unwrap();
    store
        .commit(&key, value.conversation_id, &response())
        .unwrap();
    let before: Vec<u8> = raw(&path)
        .query_row(
            "SELECT response_snapshot FROM session_bindings",
            [],
            |row| row.get(0),
        )
        .unwrap();
    raw(&path)
        .execute("UPDATE session_bindings SET response_codec_version = 2", [])
        .unwrap();
    assert_eq!(
        store.commit(&key, value.conversation_id, &response()),
        Err(BindingError::SerializationFailed)
    );
    let after: Vec<u8> = raw(&path)
        .query_row(
            "SELECT response_snapshot FROM session_bindings",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(after, before);
}
