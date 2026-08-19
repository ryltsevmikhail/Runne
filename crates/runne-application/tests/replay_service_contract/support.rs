
use std::sync::Arc;

use async_trait::async_trait;
use runne_application::ports::{
    ReplayAuthorizationLease, ReplayAuthorizationPort, ReplayAuthorizationRequest, ReplayError,
    ReplayEvent, ReplayOpenResult, ReplaySession, ReplayStorePort, RetentionManifest,
};
use runne_application::replay_service::{
    REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES, REPLAY_EVENT_VARIABLE_MAX_BYTES,
    REPLAY_FRAME_CAPACITY_BYTES, REPLAY_PAGE_CAPACITY_BYTES,
    measured_conversation_replay_event_bytes, measured_taskrun_replay_event_bytes,
    validate_replay_reader_capacity, validate_replay_writer_event_size,
};
use runne_application::replay_service::{ReplayDeliveryPrecommitGuard, ReplayService};
use runne_domain::conversation::ConversationEvent;
use runne_domain::id::{AttemptId, EventLogLineageId, IntegrityDigest, MessageId, TaskRunId};
use runne_domain::message::{MAX_MESSAGE_TEXT_BYTES, MessageText};
use runne_domain::replay::{
    CURSOR_SCHEMA_VERSION, ReplayCursor, ReplayScope, RetentionManifest as DomainRetentionManifest,
};
use runne_domain::task_run::TaskRunEvent;

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
            runne_domain::event::Sensitivity::Sensitive,
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
        _: Arc<dyn ReplayDeliveryPrecommitGuard>,
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
        _: Arc<dyn ReplayDeliveryPrecommitGuard>,
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
