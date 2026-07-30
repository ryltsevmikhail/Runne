//! Контрактные тесты cursor integrity ReplayService.

use std::sync::Arc;

use async_trait::async_trait;
use gocode_application::ports::{
    ReplayAuthorizationLease, ReplayAuthorizationPort, ReplayAuthorizationRequest, ReplayError,
    ReplayEvent, ReplayOpenResult, ReplaySession, ReplayStorePort, RetentionManifest,
};
use gocode_application::replay_service::{
    REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES, REPLAY_EVENT_VARIABLE_MAX_BYTES,
    REPLAY_FRAME_CAPACITY_BYTES, REPLAY_PAGE_CAPACITY_BYTES,
    measured_conversation_replay_event_bytes, measured_taskrun_replay_event_bytes,
    validate_replay_reader_capacity, validate_replay_writer_event_size,
};
use gocode_application::replay_service::{ReplayDeliveryPrecommitGuard, ReplayService};
use gocode_domain::conversation::ConversationEvent;
use gocode_domain::id::{AttemptId, EventLogLineageId, IntegrityDigest, MessageId, TaskRunId};
use gocode_domain::message::{MAX_MESSAGE_TEXT_BYTES, MessageText};
use gocode_domain::replay::{
    CURSOR_SCHEMA_VERSION, ReplayCursor, ReplayScope, RetentionManifest as DomainRetentionManifest,
};
use gocode_domain::task_run::TaskRunEvent;

struct DummyStore;

struct AvailableDeliveryGuard;

struct DenyAuthorization;

struct AllowAuthorization;

impl ReplayAuthorizationPort for AllowAuthorization {
    fn current_lease(
        &self,
        request: &ReplayAuthorizationRequest,
    ) -> Result<ReplayAuthorizationLease, ReplayError> {
        ReplayAuthorizationLease::new(
            request.principal_id.clone(),
            request.expected_epoch,
            gocode_domain::event::Sensitivity::Sensitive,
        )
    }
}

fn allow_authorization() -> Arc<dyn ReplayAuthorizationPort> {
    Arc::new(AllowAuthorization)
}

impl ReplayAuthorizationPort for DenyAuthorization {
    fn current_lease(
        &self,
        _request: &ReplayAuthorizationRequest,
    ) -> Result<ReplayAuthorizationLease, ReplayError> {
        Err(ReplayError::AuthorizationRevoked)
    }
}

impl ReplayDeliveryPrecommitGuard for AvailableDeliveryGuard {
    fn inspect(
        &self,
        _session: &ReplaySession,
        _events: &[ReplayEvent],
    ) -> Result<(), ReplayError> {
        Ok(())
    }
}

fn delivery_guard() -> Arc<dyn ReplayDeliveryPrecommitGuard> {
    Arc::new(AvailableDeliveryGuard)
}

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
        _: &EventLogLineageId,
        _: &[u8; 32],
        _: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<ReplayOpenResult, ReplayError> {
        Err(ReplayError::Storage("dummy".into()))
    }
    async fn retention_manifest(
        &self,
        _: &EventLogLineageId,
        _: &[u8; 32],
    ) -> Result<RetentionManifest, ReplayError> {
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
        _: Arc<dyn ReplayDeliveryPrecommitGuard>,
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
        _: Arc<dyn ReplayDeliveryPrecommitGuard>,
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
        _: Arc<dyn ReplayDeliveryPrecommitGuard>,
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

#[tokio::test]
async fn public_constructor_requires_and_uses_independent_authorization() {
    let service = ReplayService::new(
        Arc::new(DummyStore),
        [0xCC; 32],
        EventLogLineageId::from_bytes([4; 16]),
        Arc::new(DenyAuthorization),
    );

    let error = service
        .open_session("user", 1, &[5; 16], 0, 1, &[2; 16], None, delivery_guard())
        .await
        .unwrap_err();

    assert!(matches!(error, ReplayError::AuthorizationRevoked));
}

#[test]
fn cursor_integrity_rejects_tampering() {
    let lineage = EventLogLineageId::from_bytes([4; 16]);
    let service = ReplayService::new(
        Arc::new(DummyStore),
        [0xCC; 32],
        lineage,
        allow_authorization(),
    );
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
        delivery_guard(),
    ));
    assert!(matches!(result, Err(ReplayError::CursorInvalid { .. })));
}

#[test]
fn cursor_construction_is_deterministic() {
    let service = ReplayService::new(
        Arc::new(DummyStore),
        [0xCC; 32],
        EventLogLineageId::from_bytes([4; 16]),
        allow_authorization(),
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
        allow_authorization(),
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
        allow_authorization(),
    );
    let cursor = service.build_cursor_from_event(&event(), &scope()).unwrap();

    assert!(service.validate_cursor_integrity(&cursor).is_ok());
}

#[test]
fn cursor_rejects_wrong_server_secret() {
    let lineage = EventLogLineageId::from_bytes([4; 16]);
    let issuing_service = ReplayService::new(
        Arc::new(DummyStore),
        [0xCC; 32],
        lineage,
        allow_authorization(),
    );
    let cursor = issuing_service
        .build_cursor_from_event(&event(), &scope())
        .unwrap();
    let validating_service = ReplayService::new(
        Arc::new(DummyStore),
        [0xDD; 32],
        lineage,
        allow_authorization(),
    );

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
        allow_authorization(),
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
        allow_authorization(),
    );
    let cursor = issuing_service
        .build_cursor_from_event(&event(), &scope())
        .unwrap();
    let validating_service = ReplayService::new(
        Arc::new(DummyStore),
        [0xCC; 32],
        EventLogLineageId::from_bytes([5; 16]),
        allow_authorization(),
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

#[test]
fn readiness_rejects_retained_event_that_cannot_fit_frame_plus_overhead() {
    let maximum_event_bytes =
        REPLAY_FRAME_CAPACITY_BYTES - REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES + 1;
    let manifest = DomainRetentionManifest::new(
        EventLogLineageId::from_bytes([4; 16]),
        0,
        Some(1),
        1,
        maximum_event_bytes,
        IntegrityDigest::from_bytes([9; 32]),
    )
    .unwrap();

    assert!(matches!(
        validate_replay_reader_capacity(
            &manifest,
            REPLAY_FRAME_CAPACITY_BYTES,
            REPLAY_PAGE_CAPACITY_BYTES,
            REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES,
        ),
        Err(ReplayError::Integrity(_))
    ));
}

#[test]
fn readiness_accepts_exact_frame_capacity_without_truncation() {
    let maximum_event_bytes =
        REPLAY_FRAME_CAPACITY_BYTES - REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES;
    let manifest = DomainRetentionManifest::new(
        EventLogLineageId::from_bytes([4; 16]),
        0,
        Some(1),
        1,
        maximum_event_bytes,
        IntegrityDigest::from_bytes([9; 32]),
    )
    .unwrap();

    validate_replay_reader_capacity(
        &manifest,
        REPLAY_FRAME_CAPACITY_BYTES,
        REPLAY_PAGE_CAPACITY_BYTES,
        REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES,
    )
    .unwrap();
}

#[test]
fn readiness_rejects_empty_inventory_when_future_append_limit_exceeds_reader() {
    let manifest = DomainRetentionManifest::new(
        EventLogLineageId::from_bytes([4; 16]),
        0,
        None,
        0,
        0,
        IntegrityDigest::from_bytes([9; 32]),
    )
    .unwrap();

    assert!(matches!(
        validate_replay_reader_capacity(
            &manifest,
            REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES + 1,
            REPLAY_PAGE_CAPACITY_BYTES,
            REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES,
        ),
        Err(ReplayError::Integrity(_))
    ));
}

#[test]
fn writer_rejects_exact_canonical_event_expanded_by_json_escaping() {
    let mut replay_event = event();
    replay_event.aggregate_type = 2;
    replay_event.correlation_type = 2;
    let payload = ConversationEvent::UserMessageAppended {
        message_id: MessageId::from_bytes([0x11; 16]),
        taskrun_id: TaskRunId::from_bytes([0x22; 16]),
        attempt_id: AttemptId::from_bytes([0x33; 16]),
        text: MessageText::new("\0".repeat(MAX_MESSAGE_TEXT_BYTES)).unwrap(),
    };

    let actual = measured_conversation_replay_event_bytes(&replay_event, &payload).unwrap();

    assert!(actual > REPLAY_EVENT_VARIABLE_MAX_BYTES);
    assert!(matches!(
        validate_replay_writer_event_size(actual),
        Err(ReplayError::Integrity(_))
    ));
}

#[test]
fn writer_rejects_durable_payload_whose_hex_transport_exceeds_frame_budget() {
    let mut replay_event = event();
    replay_event.payload = vec![0xab; (REPLAY_EVENT_VARIABLE_MAX_BYTES / 2) + 1];

    let actual =
        measured_taskrun_replay_event_bytes(&replay_event, &TaskRunEvent::TaskRunCreated).unwrap();

    assert!(actual > REPLAY_EVENT_VARIABLE_MAX_BYTES);
    assert!(matches!(
        validate_replay_writer_event_size(actual),
        Err(ReplayError::Integrity(_))
    ));
}
