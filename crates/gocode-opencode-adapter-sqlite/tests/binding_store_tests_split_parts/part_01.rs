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
        "../../../../docs/schemas/session-info-v1.schema.json"
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
