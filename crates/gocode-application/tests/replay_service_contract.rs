//! Контрактные тесты cursor integrity ReplayService.

use std::sync::Arc;

use async_trait::async_trait;
use gocode_application::ports::{ReplayError, ReplayEvent, ReplaySession, ReplayStorePort};
use gocode_application::replay_service::ReplayService;
use gocode_domain::id::EventLogLineageId;
use gocode_domain::replay::{CURSOR_SCHEMA_VERSION, ReplayCursor, ReplayScope};

struct DummyStore;

fn event() -> ReplayEvent {
    ReplayEvent {
        global_position: 42,
        event_id: [1; 16],
        aggregate_type: 1,
        aggregate_id: [2; 16],
        payload: vec![],
        timestamp: 0,
        event_type: "TaskRunEvent".into(),
        sequence: 7,
        sensitivity: 0,
        schema_version: 8,
        causation_id: None,
        command_id: [5; 16],
        idempotency_key: "replay-test".into(),
        actor: "test-actor".into(),
        integrity_digest: [6; 32],
        correlation_id: [3; 16],
        correlation_type: 1,
        integrity_profile: 1,
    }
}

fn scope() -> ReplayScope {
    ReplayScope::Aggregate {
        aggregate_type: 1,
        aggregate_id: [2; 16],
    }
}

#[async_trait]
impl ReplayStorePort for DummyStore {
    async fn open_session(
        &self,
        _: &str,
        _: i64,
        _: &[u8; 16],
        _: i64,
        _: i32,
        _: &[u8; 16],
        _: Option<&ReplayCursor>,
        _: &[u8; 32],
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        Err(ReplayError::Storage("dummy".into()))
    }
    async fn read_page(
        &self,
        _: &[u8; 16],
        _: &str,
        _: i64,
        _: &[u8; 16],
        _: i64,
        _: usize,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        Err(ReplayError::Storage("dummy".into()))
    }
    async fn acknowledge(
        &self,
        _: &[u8; 16],
        _: &str,
        _: i64,
        _: &[u8; 16],
        _: i64,
        _: &ReplayCursor,
    ) -> Result<(), ReplayError> {
        Err(ReplayError::Storage("dummy".into()))
    }
    async fn complete_catch_up(
        &self,
        _: &[u8; 16],
        _: &str,
        _: i64,
        _: &[u8; 16],
        _: i64,
        _: &[u8; 32],
    ) -> Result<(ReplaySession, Option<ReplayEvent>), ReplayError> {
        Err(ReplayError::Storage("dummy".into()))
    }
    async fn continue_live(
        &self,
        _: &[u8; 16],
        _: &str,
        _: i64,
        _: &[u8; 16],
        _: i64,
    ) -> Result<ReplaySession, ReplayError> {
        Err(ReplayError::Storage("dummy".into()))
    }
    async fn poll_live(
        &self,
        _: &[u8; 16],
        _: &str,
        _: i64,
        _: &[u8; 16],
        _: i64,
    ) -> Result<(ReplaySession, Vec<ReplayEvent>), ReplayError> {
        Err(ReplayError::Storage("dummy".into()))
    }
    async fn close_session(
        &self,
        _: &[u8; 16],
        _: &str,
        _: i64,
        _: &[u8; 16],
        _: i64,
    ) -> Result<(), ReplayError> {
        Err(ReplayError::Storage("dummy".into()))
    }
}

#[test]
fn cursor_integrity_rejects_tampering() {
    let lineage = EventLogLineageId::from_bytes([4; 16]);
    let service = ReplayService::new(Arc::new(DummyStore), [0xCC; 32], lineage);
    let event = event();
    let scope = scope();
    let mut cursor = service.build_cursor_from_event(&event, &scope).unwrap();
    cursor.global_position = 43;
    let result = futures::executor::block_on(service.open_session(
        "user",
        1,
        &[5; 16],
        0,
        1,
        &[2; 16],
        Some(cursor),
    ));
    assert!(matches!(result, Err(ReplayError::CursorInvalid { .. })));
}

#[test]
fn cursor_construction_is_deterministic() {
    let service = ReplayService::new(
        Arc::new(DummyStore),
        [0xCC; 32],
        EventLogLineageId::from_bytes([4; 16]),
    );
    let event = event();
    let scope = scope();

    assert_eq!(
        service.build_cursor_from_event(&event, &scope).unwrap(),
        service.build_cursor_from_event(&event, &scope).unwrap(),
    );
}

#[test]
fn cursor_construction_rejects_invalid_delivered_event_metadata() {
    let service = ReplayService::new(
        Arc::new(DummyStore),
        [0xCC; 32],
        EventLogLineageId::from_bytes([4; 16]),
    );
    let mut invalid = event();
    invalid.sequence = 0;

    assert!(matches!(
        service.build_cursor_from_event(&invalid, &scope()),
        Err(ReplayError::Integrity(_))
    ));
}

#[test]
fn cursor_integrity_accepts_valid_cursor() {
    let service = ReplayService::new(
        Arc::new(DummyStore),
        [0xCC; 32],
        EventLogLineageId::from_bytes([4; 16]),
    );
    let cursor = service.build_cursor_from_event(&event(), &scope()).unwrap();

    assert!(service.validate_cursor_integrity(&cursor).is_ok());
}

#[test]
fn cursor_rejects_wrong_server_secret() {
    let lineage = EventLogLineageId::from_bytes([4; 16]);
    let issuing_service = ReplayService::new(Arc::new(DummyStore), [0xCC; 32], lineage);
    let cursor = issuing_service
        .build_cursor_from_event(&event(), &scope())
        .unwrap();
    let validating_service = ReplayService::new(Arc::new(DummyStore), [0xDD; 32], lineage);

    assert!(matches!(
        validating_service.validate_cursor_integrity(&cursor),
        Err(ReplayError::CursorInvalid { .. })
    ));
}

#[test]
fn cursor_rejects_wrong_schema_version() {
    let service = ReplayService::new(
        Arc::new(DummyStore),
        [0xCC; 32],
        EventLogLineageId::from_bytes([4; 16]),
    );
    let mut cursor = service.build_cursor_from_event(&event(), &scope()).unwrap();
    cursor.schema_version = CURSOR_SCHEMA_VERSION + 1;

    assert!(matches!(
        service.validate_cursor_integrity(&cursor),
        Err(ReplayError::CursorInvalid { .. })
    ));
}

#[test]
fn cursor_rejects_foreign_event_log_lineage() {
    let issuing_service = ReplayService::new(
        Arc::new(DummyStore),
        [0xCC; 32],
        EventLogLineageId::from_bytes([4; 16]),
    );
    let cursor = issuing_service
        .build_cursor_from_event(&event(), &scope())
        .unwrap();
    let validating_service = ReplayService::new(
        Arc::new(DummyStore),
        [0xCC; 32],
        EventLogLineageId::from_bytes([5; 16]),
    );

    assert!(matches!(
        validating_service.validate_cursor_integrity(&cursor),
        Err(ReplayError::CursorInvalid { .. })
    ));
}

#[test]
fn scope_digest_is_deterministic() {
    let scope = scope();

    assert_eq!(scope.canonical_digest(), scope.canonical_digest());
}

#[test]
fn scope_digest_differs_for_different_scopes() {
    let first = scope();
    let second = ReplayScope::Aggregate {
        aggregate_type: 1,
        aggregate_id: [3; 16],
    };

    assert_ne!(first.canonical_digest(), second.canonical_digest());
}
