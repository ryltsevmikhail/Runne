use super::*;
use async_trait::async_trait;
use gocode_api::{
    ApiReplayAggregateKind, ReplayPromotionProjectionV1, ReplayRetentionBaselineWireV2,
    UnauthenticatedReplayPromotionProjectionV1, UnauthenticatedReplayRetentionBaselineFieldsV2,
};
use gocode_application::local_session::{
    BootstrapProof, LocalSessionService, bootstrap_proof_transcript,
};
use gocode_application::ports::{
    ReplayError, ReplayEvent, ReplayOpenResult, ReplaySession, ReplayState, ReplayStorePort,
};
use gocode_application::replay_service::{ReplayDeliveryPrecommitGuard, ReplayService};
use gocode_domain::event::{Actor, EventEnvelope, Sensitivity};
use gocode_domain::id::{
    AggregateId, CommandId, EventId, IdempotencyKey, IntegrityDigest, TaskRunId,
};
use gocode_domain::replay::{ReplayCursor, ReplayScope, RetentionManifest};
use gocode_domain::task_run::{TaskRun, TaskRunEvent};
use gocode_domain::timestamp::Timestamp;
use hmac::{Hmac, Mac};
use rusqlite::{Connection, params};
use sha2::Sha256;
use std::sync::mpsc::{Receiver, Sender};

type HmacSha256 = Hmac<Sha256>;
const V2_HEAD: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 0x31,
];

include!("replay_authorization_resume_v2/helpers.rs");

struct TransactionalAdmissionStore {
    connection: Mutex<Connection>,
    entered: Sender<()>,
    release: Mutex<Receiver<()>>,
}

#[async_trait]
impl ReplayStorePort for TransactionalAdmissionStore {
    async fn resume_session_from_baseline_v2(
        &self,
        request: gocode_application::ports::ReplayBaselineResumeRequestV2,
        _: &EventLogLineageId,
        _: &[u8; 32],
        guard: Arc<dyn ReplayDeliveryPrecommitGuard>,
    ) -> Result<
        (
            ReplaySession,
            Vec<ReplayEvent>,
            ReplayEvent,
            gocode_application::ports::ReplayAcceptedPromotionV2,
        ),
        ReplayError,
    > {
        let session = ReplaySession {
            session_id: [0xA1; 16],
            principal_id: request.principal_id().to_owned(),
            session_generation: request.session_generation(),
            authority_id: *request.authority_id(),
            authorization_epoch: request.authorization_epoch(),
            aggregate_type: request.aggregate_type(),
            aggregate_id: *request.aggregate_id(),
            retained_floor: Some(request.retained_floor()),
            retention_generation: 0,
            high_water_position: request.captured_high_water(),
            next_page_position: None,
            last_delivered_position: Some(request.baseline_global_position()),
            last_acked_position: Some(request.baseline_global_position()),
            state: ReplayState::CatchingUp,
            high_water_ref: vec![1],
            catch_up_completion: None,
            live_delivery_id: None,
            created_at: "daemon-v2-test".to_owned(),
        };
        let persisted = guard.mutate_session_admission(&session, &[], &mut || {
            let mut connection = self.connection.lock().unwrap();
            let transaction = connection.transaction().map_err(|error| ReplayError::Storage(error.to_string()))?;
            transaction.execute(
                "INSERT INTO _replay_subscriptions (session_id, principal_id, session_generation, authority_id, authorization_epoch, aggregate_type, aggregate_id, retained_floor, retention_generation, high_water_position, state, high_water_ref, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9, 'catching_up', ?10, 'daemon-v2-test')",
                params![session.session_id.as_slice(), session.principal_id, session.session_generation, session.authority_id.as_slice(), session.authorization_epoch, session.aggregate_type, session.aggregate_id.as_slice(), session.retained_floor, session.high_water_position, session.high_water_ref],
            ).map_err(|error| ReplayError::Storage(error.to_string()))?;
            let epoch: i64 = transaction.query_row(
                "SELECT authorization_epoch FROM _replay_subscriptions WHERE session_id = ?1",
                [session.session_id.as_slice()],
                |row| row.get(0),
            ).map_err(|error| ReplayError::Storage(error.to_string()))?;
            if epoch != session.authorization_epoch {
                return Err(ReplayError::Integrity("V2 admission readback changed epoch".to_owned()));
            }
            self.entered.send(()).map_err(|_| ReplayError::Storage("test admission receiver dropped".to_owned()))?;
            self.release.lock().unwrap().recv().map_err(|_| ReplayError::Storage("test admission release dropped".to_owned()))?;
            transaction.commit().map_err(|error| ReplayError::Storage(error.to_string()))?;
            Ok(session.clone())
        })?;
        Ok((
            persisted,
            vec![],
            ReplayEvent {
                global_position: request.baseline_global_position(),
                event_id: [1; 16],
                aggregate_type: request.aggregate_type(),
                aggregate_id: *request.aggregate_id(),
                payload: vec![],
                timestamp: 1,
                event_type: "baseline".into(),
                sequence: i64::try_from(request.sequence()).unwrap(),
                sensitivity: 0,
                schema_version: 1,
                causation_id: None,
                command_id: [1; 16],
                idempotency_key: "baseline".into(),
                actor: "test".into(),
                integrity_digest: [1; 32],
                correlation_id: *request.aggregate_id(),
                correlation_type: request.aggregate_type(),
                integrity_profile: 1,
            },
            gocode_application::ports::ReplayAcceptedPromotionV2::from_storage(
                gocode_application::ports::ReplayAcceptedPromotionV2Parts {
                    codec: 1,
                    bytes: request.promotion_projection_bytes().to_vec(),
                    digest: *request.promotion_projection_digest(),
                    sequence: request.sequence(),
                    version: request.version(),
                    global_position: request.baseline_global_position(),
                    head_event_id: *request.head_event_id(),
                    head_integrity_digest: *request.head_integrity_digest(),
                    captured_high_water: request.captured_high_water(),
                },
            )?,
        ))
    }

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
        Err(ReplayError::Storage("unused".to_owned()))
    }
    async fn retention_manifest(
        &self,
        _: &EventLogLineageId,
        _: &[u8; 32],
    ) -> Result<RetentionManifest, ReplayError> {
        Err(ReplayError::Storage("unused".to_owned()))
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
        Err(ReplayError::Storage("unused".to_owned()))
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
        Err(ReplayError::Storage("unused".to_owned()))
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
        Err(ReplayError::Storage("unused".to_owned()))
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
        Err(ReplayError::Storage("unused".to_owned()))
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
        Err(ReplayError::Storage("unused".to_owned()))
    }
    async fn close_session(
        &self,
        _: &[u8; 16],
        _: &str,
        _: i64,
        _: &[u8; 16],
        _: i64,
    ) -> Result<(), ReplayError> {
        Err(ReplayError::Storage("unused".to_owned()))
    }
}

fn v2_resume_wire(
    binding: &RuntimeSessionBinding,
    secret: [u8; 32],
) -> ReplayRetentionBaselineWireV2 {
    let aggregate_id = *binding.stable().authority_id();
    let event = EventEnvelope::from_parts(
        EventId::from_bytes(V2_HEAD),
        AggregateId::TaskRun(TaskRunId::from_bytes(aggregate_id)),
        AggregateId::TaskRun(TaskRunId::from_bytes(aggregate_id)),
        None,
        CommandId::from_bytes([0xE2; 16]),
        IdempotencyKey::new("daemon-v2-admission").unwrap(),
        1,
        Actor::new("daemon-test").unwrap(),
        Sensitivity::Public,
        TaskRunEvent::TaskRunCreated,
        1,
        Timestamp::from_unix_micros(1),
        IntegrityDigest::from_bytes([0xE3; 32]),
    );
    let bytes = ReplayPromotionProjectionV1::encode_task_run(
        &TaskRun::replay(&[event]).unwrap().snapshot_v1(),
    )
    .unwrap();
    let projection = UnauthenticatedReplayPromotionProjectionV1::decode(&bytes).unwrap();
    let gocode_api::ReplayPromotionProjectionViewV1::TaskRun(value) = projection.view() else {
        unreachable!()
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let scope = ReplayScope::Aggregate {
        aggregate_type: 1,
        aggregate_id,
    };
    let mut fields = UnauthenticatedReplayRetentionBaselineFieldsV2 {
        schema_version: 2,
        authority_id: aggregate_id,
        principal_id: "local-owner".to_owned(),
        lineage_id: *binding.stable().lineage_id().as_bytes(),
        runtime_session_binding_digest: binding.canonical_digest(),
        replay_scope_digest: scope.canonical_digest(),
        aggregate_kind: ApiReplayAggregateKind::TaskRun,
        aggregate_id,
        sequence: 1,
        version: 1,
        baseline_global_position: 1,
        head_event_id: V2_HEAD,
        head_integrity_digest: [0xE3; 32],
        promotion_codec: 1,
        promotion_projection_bytes: bytes,
        promotion_projection_digest: *value.promotion_digest(),
        retained_floor: 1,
        captured_high_water: 1,
        retention_generation: 1,
        retention_manifest_digest: [0xE4; 32],
        issued_at_unix_ms: now,
        expires_at_unix_ms: now + 10_000,
        witness_mac: [0; 32],
    };
    let unsigned = ReplayRetentionBaselineWireV2::from_unauthenticated_fields(fields.clone());
    let mut derive = HmacSha256::new_from_slice(&secret).unwrap();
    derive.update(gocode_api::REPLAY_RETENTION_BASELINE_KEY_DOMAIN_V2);
    derive.update(&binding.canonical_digest());
    let key = derive.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&key).unwrap();
    mac.update(&gocode_api::replay_retention_baseline_v2_transcript(&unsigned).unwrap());
    fields.witness_mac = mac.finalize().into_bytes().into();
    ReplayRetentionBaselineWireV2::from_unauthenticated_fields(fields)
}

include!("replay_authorization_resume_v2/fence.rs");
