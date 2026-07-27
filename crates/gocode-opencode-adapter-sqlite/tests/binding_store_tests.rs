use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use gocode_api::{
    ApiActor, ApiPrincipalId, NonNegativeUnixMillis, OpenCodeSessionInfo, ResponseSeed,
};
use gocode_domain::id::{CommandId, ConversationId, IdempotencyKey, WorkspaceId};
use gocode_opencode_adapter_sqlite::{BindingClock, SqliteSessionBindingStore};
use gocode_opencode_compat::profile::ProfileId;
use gocode_opencode_compat::{
    BindingError, BindingRuntimeAuthorityId, EnsurePendingResult, OpenCodeSessionId,
    SessionBindingContext, SessionBindingKey, SessionBindingStatus, SessionBindingStore,
    SessionCreateFingerprint,
};

#[test]
fn opens_a_binding_store() {
    let _store = SqliteSessionBindingStore::open(db_path()).expect("open");
}

fn db_path() -> std::path::PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    std::env::temp_dir().join(format!(
        "gocode-binding-test-{}-{}-{}.sqlite",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ))
}

fn key() -> SessionBindingKey {
    SessionBindingKey {
        session_id: OpenCodeSessionId::new("session-a").expect("valid session"),
        profile_id: ProfileId::new("profile-a").expect("profile"),
        profile_revision: 2,
        runtime_authority_id: BindingRuntimeAuthorityId::new("authority-a")
            .expect("valid authority"),
    }
}

fn context() -> SessionBindingContext {
    SessionBindingContext {
        conversation_id: ConversationId::from_str("018f2e3a-7000-7000-8000-000000000001")
            .expect("uuid"),
        workspace_id: WorkspaceId::from_str("018f2e3a-7000-7000-8000-000000000002").expect("uuid"),
        command_id: CommandId::from_str("018f2e3a-7000-7000-8000-000000000003").expect("uuid"),
        idempotency_key: IdempotencyKey::new("request-a").expect("key"),
        request_fingerprint: SessionCreateFingerprint::from_bytes([7; 32]),
        title: Some("A title".to_owned()),
        principal: ApiPrincipalId::new("principal-a").expect("principal"),
        actor: ApiActor::new("actor-a").expect("actor"),
        response_seed: ResponseSeed {
            project_id: "project-a".to_owned(),
            directory: "/tmp".to_owned(),
            path: None,
            version: "1.0".to_owned(),
            workspace_id: None,
        },
    }
}

fn response() -> OpenCodeSessionInfo {
    let schema_value = serde_json::from_str(include_str!(
        "../../../docs/schemas/session-info-v1.schema.json"
    ))
    .expect("schema JSON");
    let schema = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema_value)
        .expect("schema compile");
    OpenCodeSessionInfo::from_json(serde_json::json!({"id":"session-a","slug":"a","projectID":"project-a","directory":"/tmp","title":"A title","version":"1.0","time":{"created":1,"updated":1}}), &schema).expect("response")
}

#[test]
fn persists_exact_context_and_idempotent_commit() {
    let store = SqliteSessionBindingStore::open(db_path()).expect("open");
    let key = key();
    let context = context();
    assert_eq!(
        store.ensure_pending(&key, &context),
        Ok(EnsurePendingResult::Created)
    );
    assert_eq!(
        store.ensure_pending(&key, &context),
        Ok(EnsurePendingResult::AlreadyPending)
    );
    let response = response();
    assert_eq!(
        store.commit(&key, context.conversation_id, &response),
        Ok(())
    );
    assert_eq!(
        store.commit(&key, context.conversation_id, &response),
        Ok(())
    );
    assert_eq!(
        store.lookup(&key),
        Ok(Some(SessionBindingStatus::Committed { context, response }))
    );
}

#[test]
fn rejects_context_and_commit_conflicts_without_mutation() {
    let store = SqliteSessionBindingStore::open(db_path()).expect("open");
    let key = key();
    let context = context();
    assert_eq!(
        store.ensure_pending(&key, &context),
        Ok(EnsurePendingResult::Created)
    );
    let mut conflicting = context.clone();
    conflicting.title = Some("other".to_owned());
    assert_eq!(
        store.ensure_pending(&key, &conflicting),
        Err(BindingError::Conflict(key.clone()))
    );
    let other = ConversationId::from_str("018f2e3a-7000-7000-8000-000000000004").expect("uuid");
    assert_eq!(
        store.commit(&key, other, &response()),
        Err(BindingError::Conflict(key.clone()))
    );
    assert_eq!(
        store.lookup(&key),
        Ok(Some(SessionBindingStatus::Pending { context }))
    );
}

#[test]
fn reopens_wal_database_with_exact_pending_context() {
    let path = db_path();
    let key = key();
    let context = context();
    {
        let store = SqliteSessionBindingStore::open(&path).expect("open");
        assert_eq!(
            store.ensure_pending(&key, &context),
            Ok(EnsurePendingResult::Created)
        );
    }
    let reopened = SqliteSessionBindingStore::open(&path).expect("reopen");
    assert_eq!(
        reopened.lookup(&key),
        Ok(Some(SessionBindingStatus::Pending { context }))
    );
}

struct FixedClock(Result<NonNegativeUnixMillis, BindingError>);
impl BindingClock for FixedClock {
    fn now_millis(&self) -> Result<NonNegativeUnixMillis, BindingError> {
        self.0.clone()
    }
}

#[test]
fn retry_does_not_read_a_failed_clock_and_cursor_must_be_live() {
    let path = db_path();
    let created = SqliteSessionBindingStore::open_with_clock(
        &path,
        std::sync::Arc::new(FixedClock(Ok(NonNegativeUnixMillis::new(9).expect("time")))),
    )
    .expect("open");
    let key = key();
    let context = context();
    assert_eq!(
        created.ensure_pending(&key, &context),
        Ok(EnsurePendingResult::Created)
    );
    let retry = SqliteSessionBindingStore::open_with_clock(
        &path,
        std::sync::Arc::new(FixedClock(Err(BindingError::StorageFailure))),
    )
    .expect("reopen");
    assert_eq!(
        retry.ensure_pending(&key, &context),
        Ok(EnsurePendingResult::AlreadyPending)
    );
    let fake = (NonNegativeUnixMillis::new(9).expect("time"), key.clone());
    assert_eq!(
        retry.list_pending(&key.runtime_authority_id, 1, Some(&fake)),
        Ok(Vec::new())
    );
    assert_eq!(
        retry.commit(&key, context.conversation_id, &response()),
        Ok(())
    );
    assert_eq!(
        retry.list_pending(&key.runtime_authority_id, 1, Some(&fake)),
        Err(BindingError::Conflict(key))
    );
}

fn raw(path: &std::path::Path) -> rusqlite::Connection {
    rusqlite::Connection::open(path).expect("raw connection")
}

fn rows(path: &std::path::Path) -> i64 {
    raw(path)
        .query_row("SELECT COUNT(*) FROM session_bindings", [], |row| {
            row.get(0)
        })
        .expect("count")
}

#[derive(Debug, PartialEq, Eq)]
struct DurableRow {
    session_id: String,
    profile_id: String,
    profile_revision: i64,
    runtime_authority_id: String,
    conversation_id: Vec<u8>,
    workspace_id: Vec<u8>,
    command_id: Vec<u8>,
    idempotency_key: Vec<u8>,
    request_fingerprint: Vec<u8>,
    context_codec_version: i64,
    context_snapshot: Vec<u8>,
    response_codec_version: i64,
    response_snapshot: Option<Vec<u8>>,
    created_at: i64,
    status: String,
}

fn full_row(path: &std::path::Path) -> DurableRow {
    raw(path)
        .query_row(
            "SELECT session_id, profile_id, profile_revision, runtime_authority_id, conversation_id, workspace_id, command_id, idempotency_key, request_fingerprint, context_codec_version, context_snapshot, response_codec_version, response_snapshot, created_at, status FROM session_bindings",
            [],
            |row| Ok(DurableRow {
                session_id: row.get(0)?, profile_id: row.get(1)?, profile_revision: row.get(2)?, runtime_authority_id: row.get(3)?,
                conversation_id: row.get(4)?, workspace_id: row.get(5)?, command_id: row.get(6)?, idempotency_key: row.get(7)?,
                request_fingerprint: row.get(8)?, context_codec_version: row.get(9)?, context_snapshot: row.get(10)?,
                response_codec_version: row.get(11)?, response_snapshot: row.get(12)?, created_at: row.get(13)?, status: row.get(14)?,
            }),
        )
        .unwrap()
}

fn singleton(path: &std::path::Path) -> i64 {
    raw(path)
        .query_row(
            "SELECT last_created_at FROM gocode_session_binding_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

fn another_key(n: u8) -> SessionBindingKey {
    SessionBindingKey {
        session_id: OpenCodeSessionId::new(format!("session-{n}")).unwrap(),
        ..key()
    }
}

fn another_context(n: u8) -> SessionBindingContext {
    let mut value = context();
    value.command_id =
        CommandId::from_str(&format!("018f2e3a-7000-7000-8000-0000000000{n:02x}")).unwrap();
    value.idempotency_key = IdempotencyKey::new(format!("request-{n}")).unwrap();
    value
}

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

#[test]
fn response_corruption_fails_closed_without_mutation() {
    for (name, sql) in [
        (
            "codec-version",
            "UPDATE session_bindings SET response_codec_version = 2",
        ),
        (
            "trailing-whitespace",
            "UPDATE session_bindings SET response_snapshot = CAST(response_snapshot || X'20' AS BLOB)",
        ),
        (
            "noncanonical-order",
            "UPDATE session_bindings SET response_snapshot = X'7b226964223a2273657373696f6e2d61222c226469726563746f7279223a222f746d70222c2270726f6a6563744944223a2270726f6a6563742d61222c22736c7567223a2261222c2274696d65223a7b2263726561746564223a312c2275706461746564223a317d2c227469746c65223a2241207469746c65222c2276657273696f6e223a22312e30227d'",
        ),
        (
            "invalid-schema",
            "UPDATE session_bindings SET response_snapshot = X'7b7d'",
        ),
        (
            "truncated",
            "UPDATE session_bindings SET response_snapshot = X'7b'",
        ),
        (
            "oversized",
            "PRAGMA ignore_check_constraints = ON; UPDATE session_bindings SET response_snapshot = zeroblob(65537); PRAGMA ignore_check_constraints = OFF;",
        ),
    ] {
        let path = db_path();
        let store = SqliteSessionBindingStore::open(&path).unwrap();
        let key = key();
        let value = context();
        let expected = response();
        store.ensure_pending(&key, &value).unwrap();
        store
            .commit(&key, value.conversation_id, &expected)
            .unwrap();
        raw(&path).execute_batch(sql).unwrap();
        let before = full_row(&path);
        let state_before = singleton(&path);
        assert_eq!(
            store.lookup(&key),
            Err(BindingError::SerializationFailed),
            "{name}"
        );
        assert_eq!(
            store.commit(&key, value.conversation_id, &expected),
            Err(BindingError::SerializationFailed),
            "{name}"
        );
        assert_eq!(full_row(&path), before, "{name}");
        assert_eq!(singleton(&path), state_before, "{name}");
    }
}

#[test]
fn commit_different_valid_response_preserves_existing_bytes() {
    let path = db_path();
    let store = SqliteSessionBindingStore::open(&path).unwrap();
    let key = key();
    let value = context();
    let first = response();
    store.ensure_pending(&key, &value).unwrap();
    store.commit(&key, value.conversation_id, &first).unwrap();
    let other = OpenCodeSessionInfo::from_json(serde_json::json!({"id":"session-a","slug":"b","projectID":"project-a","directory":"/tmp","title":"A title","version":"1.0","time":{"created":1,"updated":1}}), &jsonschema::JSONSchema::options().with_draft(jsonschema::Draft::Draft202012).compile(&serde_json::from_str(include_str!("../../../docs/schemas/session-info-v1.schema.json")).unwrap()).unwrap()).unwrap();
    let before: Vec<u8> = raw(&path)
        .query_row(
            "SELECT response_snapshot FROM session_bindings",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        store.commit(&key, value.conversation_id, &other),
        Err(BindingError::Conflict(key))
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

#[test]
fn frozen_clock_allocates_strictly_increasing_timestamps_and_overflow_inserts_nothing() {
    let path = db_path();
    let store = SqliteSessionBindingStore::open_with_clock(
        &path,
        Arc::new(FixedClock(Ok(NonNegativeUnixMillis::new(10).unwrap()))),
    )
    .unwrap();
    let first = key();
    let second = another_key(2);
    store.ensure_pending(&first, &context()).unwrap();
    store.ensure_pending(&second, &another_context(4)).unwrap();
    let times: Vec<i64> = raw(&path)
        .prepare("SELECT created_at FROM session_bindings ORDER BY created_at")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(times, vec![10, 11]);
    raw(&path)
        .execute(
            "UPDATE gocode_session_binding_state SET last_created_at = ?1",
            [i64::MAX],
        )
        .unwrap();
    assert_eq!(
        store.ensure_pending(&another_key(3), &another_context(5)),
        Err(BindingError::StorageFailure)
    );
    assert_eq!(rows(&path), 2);
}

#[test]
fn independent_connections_race_same_context_to_created_and_already_pending() {
    let path = db_path();
    let barrier = Arc::new(Barrier::new(2));
    let key = key();
    let value = context();
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let barrier = barrier.clone();
            let key = key.clone();
            let value = value.clone();
            let store = SqliteSessionBindingStore::open(&path).unwrap();
            thread::spawn(move || {
                barrier.wait();
                store.ensure_pending(&key, &value)
            })
        })
        .collect();
    let mut outcomes: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().unwrap().unwrap())
        .collect();
    outcomes.sort_by_key(|outcome| match outcome {
        EnsurePendingResult::Created => 0,
        EnsurePendingResult::AlreadyPending => 1,
        EnsurePendingResult::AlreadyCommitted => 2,
    });
    assert_eq!(
        outcomes,
        vec![
            EnsurePendingResult::Created,
            EnsurePendingResult::AlreadyPending
        ]
    );
    assert_eq!(rows(&path), 1);
    assert_eq!(
        SqliteSessionBindingStore::open(&path).unwrap().lookup(&key),
        Ok(Some(SessionBindingStatus::Pending { context: value }))
    );
}

#[test]
fn independent_connections_race_different_context_to_created_and_conflict() {
    let path = db_path();
    let barrier = Arc::new(Barrier::new(2));
    let key = key();
    let first = context();
    let mut second = first.clone();
    second.title = None;
    let handles: Vec<_> = [first.clone(), second]
        .into_iter()
        .map(|value| {
            let barrier = barrier.clone();
            let key = key.clone();
            let store = SqliteSessionBindingStore::open(&path).unwrap();
            thread::spawn(move || {
                barrier.wait();
                store.ensure_pending(&key, &value)
            })
        })
        .collect();
    let outcomes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert!(outcomes.contains(&Ok(EnsurePendingResult::Created)));
    assert!(outcomes.contains(&Err(BindingError::Conflict(key.clone()))));
    assert_eq!(rows(&path), 1);
}

#[test]
fn independent_connections_race_different_keys_with_frozen_clock() {
    let path = db_path();
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = [(key(), context()), (another_key(2), another_context(4))]
        .into_iter()
        .map(|(key, value)| {
            let barrier = barrier.clone();
            let store = SqliteSessionBindingStore::open_with_clock(
                &path,
                Arc::new(FixedClock(Ok(NonNegativeUnixMillis::new(10).unwrap()))),
            )
            .unwrap();
            thread::spawn(move || {
                barrier.wait();
                store.ensure_pending(&key, &value)
            })
        })
        .collect();
    for handle in handles {
        assert_eq!(handle.join().unwrap(), Ok(EnsurePendingResult::Created));
    }
    let created: Vec<i64> = raw(&path)
        .prepare("SELECT created_at FROM session_bindings ORDER BY created_at")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(created, vec![10, 11]);
    assert_eq!(rows(&path), 2);
    assert_eq!(singleton(&path), 11);
}

#[test]
fn future_namespaced_schema_version_is_rejected_on_open() {
    let path = db_path();
    drop(SqliteSessionBindingStore::open(&path).unwrap());
    raw(&path)
        .execute(
            "INSERT INTO gocode_session_binding_schema_version(version) VALUES (2)",
            [],
        )
        .unwrap();
    assert!(matches!(
        SqliteSessionBindingStore::open(&path),
        Err(BindingError::StorageFailure)
    ));
}

#[test]
fn missing_binding_table_is_rejected_on_open() {
    let path = db_path();
    drop(SqliteSessionBindingStore::open(&path).unwrap());
    raw(&path)
        .execute_batch("DROP TABLE session_bindings;")
        .unwrap();
    assert!(matches!(
        SqliteSessionBindingStore::open(&path),
        Err(BindingError::StorageFailure)
    ));
}

#[test]
fn missing_recovery_index_is_rejected_on_open() {
    let path = db_path();
    drop(SqliteSessionBindingStore::open(&path).unwrap());
    raw(&path)
        .execute_batch("DROP INDEX idx_session_bindings_recovery;")
        .unwrap();
    assert!(matches!(
        SqliteSessionBindingStore::open(&path),
        Err(BindingError::StorageFailure)
    ));
}

#[test]
fn missing_or_corrupt_singleton_state_is_rejected_on_open() {
    for sql in [
        "DELETE FROM gocode_session_binding_state;",
        "PRAGMA ignore_check_constraints = ON; UPDATE gocode_session_binding_state SET last_created_at = -1;",
    ] {
        let path = db_path();
        drop(SqliteSessionBindingStore::open(&path).unwrap());
        raw(&path).execute_batch(sql).unwrap();
        assert!(matches!(
            SqliteSessionBindingStore::open(&path),
            Err(BindingError::StorageFailure)
        ));
    }
}

#[test]
fn namespaced_metadata_coexists_with_store_schema_version() {
    let path = db_path();
    let conn = raw(&path);
    conn.execute_batch("CREATE TABLE schema_version (version INTEGER PRIMARY KEY); INSERT INTO schema_version VALUES (99);").unwrap();
    drop(conn);
    let store = SqliteSessionBindingStore::open(&path).unwrap();
    assert_eq!(
        store.ensure_pending(&key(), &context()),
        Ok(EnsurePendingResult::Created)
    );
    assert_eq!(
        raw(&path)
            .query_row("SELECT version FROM schema_version", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        99
    );
}

#[test]
fn pagination_is_complete_ordered_and_authority_isolated() {
    let path = db_path();
    let store = SqliteSessionBindingStore::open_with_clock(
        &path,
        Arc::new(FixedClock(Ok(NonNegativeUnixMillis::new(1).unwrap()))),
    )
    .unwrap();
    let authority = key().runtime_authority_id;
    for n in [5, 4, 3, 2, 1] {
        let key = another_key(n);
        store
            .ensure_pending(&key, &another_context(n + 10))
            .unwrap();
    }
    let mut all = Vec::new();
    let mut after = None;
    loop {
        let page = store.list_pending(&authority, 2, after.as_ref()).unwrap();
        if page.is_empty() {
            break;
        }
        after = page.last().cloned();
        all.extend(page);
    }
    assert_eq!(all.len(), 5);
    assert!(all.windows(2).all(|pair| pair[0].0 < pair[1].0));
    let other = BindingRuntimeAuthorityId::new("authority-b").unwrap();
    assert_eq!(store.list_pending(&other, 2, None), Ok(Vec::new()));
}

#[test]
fn pagination_uses_full_keyset_tiebreak_when_created_at_is_equal() {
    let path = db_path();
    let store = SqliteSessionBindingStore::open_with_clock(
        &path,
        Arc::new(FixedClock(Ok(NonNegativeUnixMillis::new(1).unwrap()))),
    )
    .unwrap();
    let authority = key().runtime_authority_id;
    let mut expected = Vec::new();
    for n in [5, 4, 3, 2, 1] {
        let key = another_key(n);
        store
            .ensure_pending(&key, &another_context(n + 10))
            .unwrap();
        expected.push(key);
    }
    raw(&path)
        .execute("UPDATE session_bindings SET created_at = 42", [])
        .unwrap();
    raw(&path)
        .execute(
            "UPDATE gocode_session_binding_state SET last_created_at = 42 WHERE singleton = 1",
            [],
        )
        .unwrap();
    expected.sort_by(|left, right| {
        (
            left.session_id.as_str(),
            left.profile_id.as_str(),
            left.profile_revision,
            left.runtime_authority_id.as_str(),
        )
            .cmp(&(
                right.session_id.as_str(),
                right.profile_id.as_str(),
                right.profile_revision,
                right.runtime_authority_id.as_str(),
            ))
    });
    let mut actual = Vec::new();
    let mut after = None;
    loop {
        let page = store.list_pending(&authority, 2, after.as_ref()).unwrap();
        if page.is_empty() {
            break;
        }
        after = page.last().cloned();
        actual.extend(page.into_iter().map(|(_, key)| key));
    }
    assert_eq!(actual, expected);
    assert_eq!(actual.len(), 5);
}

#[test]
fn pagination_rejects_invalid_limits_and_invalid_cursors() {
    let path = db_path();
    let store = SqliteSessionBindingStore::open(&path).unwrap();
    let key = key();
    store.ensure_pending(&key, &context()).unwrap();
    assert!(matches!(
        store.list_pending(&key.runtime_authority_id, 0, None),
        Err(BindingError::InvalidLimit { .. })
    ));
    assert!(matches!(
        store.list_pending(&key.runtime_authority_id, 1_001, None),
        Err(BindingError::InvalidLimit { .. })
    ));
    assert_eq!(
        store
            .list_pending(&key.runtime_authority_id, 1_000, None)
            .unwrap()
            .len(),
        1
    );
    let fake = (NonNegativeUnixMillis::new(0).unwrap(), key.clone());
    assert_eq!(
        store.list_pending(&key.runtime_authority_id, 1, Some(&fake)),
        Err(BindingError::Conflict(key.clone()))
    );
    let wrong = BindingRuntimeAuthorityId::new("other").unwrap();
    assert_eq!(
        store.list_pending(
            &wrong,
            1,
            Some(&(NonNegativeUnixMillis::new(1).unwrap(), key.clone()))
        ),
        Err(BindingError::Conflict(key))
    );
}

#[cfg(unix)]
#[test]
fn reopening_hardens_database_and_existing_sidecars_to_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let path = db_path();
    let store = SqliteSessionBindingStore::open(&path).unwrap();
    store.ensure_pending(&key(), &context()).unwrap();
    let sidecars = [
        &path,
        &std::path::PathBuf::from(format!("{}-wal", path.display())),
        &std::path::PathBuf::from(format!("{}-shm", path.display())),
    ];
    for candidate in sidecars {
        assert!(
            candidate.exists(),
            "{} must exist while connection is active",
            candidate.display()
        );
        assert_eq!(
            std::fs::metadata(candidate).unwrap().permissions().mode() & 0o077,
            0,
            "{}",
            candidate.display()
        );
        std::fs::set_permissions(candidate, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    store
        .ensure_pending(&another_key(8), &another_context(18))
        .unwrap();
    for candidate in sidecars {
        assert!(candidate.exists());
        assert_eq!(
            std::fs::metadata(candidate).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    drop(store);
    let reopened = SqliteSessionBindingStore::open(&path).unwrap();
    for candidate in sidecars {
        if candidate.exists() {
            assert_eq!(
                std::fs::metadata(candidate).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    drop(reopened);
}

#[test]
fn file_uri_is_rejected_before_sqlite_open() {
    assert!(matches!(
        SqliteSessionBindingStore::open("file:binding-test?mode=memory"),
        Err(BindingError::StorageFailure)
    ));
}

#[test]
fn stale_allocator_state_is_rejected_on_reopen() {
    let path = db_path();
    let store = SqliteSessionBindingStore::open_with_clock(
        &path,
        Arc::new(FixedClock(Ok(NonNegativeUnixMillis::new(9).unwrap()))),
    )
    .unwrap();
    store.ensure_pending(&key(), &context()).unwrap();
    drop(store);
    raw(&path)
        .execute(
            "UPDATE gocode_session_binding_state SET last_created_at = 0",
            [],
        )
        .unwrap();
    assert!(matches!(
        SqliteSessionBindingStore::open(&path),
        Err(BindingError::StorageFailure)
    ));
}
