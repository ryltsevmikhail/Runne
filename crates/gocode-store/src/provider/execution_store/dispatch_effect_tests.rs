use std::sync::atomic::{AtomicUsize, Ordering};

use futures::executor::block_on;
use gocode_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use gocode_application::provider::{ProviderCoordinatorRequest, ProviderLeaseBindingKind};
use gocode_domain::id::{AttemptId, ConversationId, TaskRunId};
use gocode_provider::{
    CancelDisposition, CancelRequest, DispatchError, DispatchRequest, ModelRef, PrepareError,
    PreparedRequest, ProviderCall, ProviderCallId, ProviderFuture, ProviderId, ProviderPort,
    ProviderStreamId, ProviderStreamItem, ReconcileRequest, ReconciliationDisposition,
    StreamCursor, StreamError,
};

use super::super::{
    ProviderCoordinatorOutcome, ProviderEffectPort, ProviderEffectStartReceipt,
    ProviderReadyEffect, ProviderRuntimeAuthorityConfig, SqliteProviderDispatchCoordinator,
    SqliteProviderDispatchStore,
};
use super::SqliteProviderExecutionStore;

struct Ready;
impl ProviderReadyEffect for Ready {
    fn into_any(self: Box<Self>) -> Box<dyn core::any::Any + Send> {
        self
    }
}

#[derive(Default)]
struct Provider {
    stages: AtomicUsize,
    sends: AtomicUsize,
}

impl ProviderPort for Provider {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call(call)
    }
    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        version: gocode_provider::ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call_for_digest_version(call, version)
    }
    fn dispatch(
        &self,
        _: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async { unreachable!() })
    }
    fn next<'a>(
        &'a self,
        _: &'a ProviderStreamId,
        _: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        Box::pin(async { unreachable!() })
    }
    fn cancel(
        &self,
        _: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        Box::pin(async { unreachable!() })
    }
    fn reconcile(
        &self,
        _: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { unreachable!() })
    }
}

impl ProviderEffectPort for Provider {
    fn stage_effect(
        &self,
        _: DispatchRequest,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        self.stages.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(Box::new(Ready) as Box<dyn ProviderReadyEffect>) })
    }
    fn dispatch_effect(
        &self,
        _: Box<dyn ProviderReadyEffect>,
        _: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(ProviderStreamId::from_bytes([1; 16])) })
    }
}

struct Guard;
impl ProhibitedContentPort for Guard {
    fn inspect(
        &self,
        _: CanonicalContentBoundary,
        _: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}

#[test]
fn lost_effect_readback_freezes_before_stage2_send() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider.sqlite");
    let dispatch = SqliteProviderDispatchStore::open(&path).unwrap();
    let execution = SqliteProviderExecutionStore::open(&path).unwrap();
    execution
        .install_runtime_authority(&ProviderRuntimeAuthorityConfig {
            runtime_authority_id: [1; 16],
            database_generation: 1,
            principal_id: "principal".into(),
            owner_id: "owner".into(),
            scope: "provider.dispatch".into(),
            generation: 1,
            fencing_token: 1,
            capability_grant_id: "grant".into(),
            capability_revision: 1,
            capability_allowed: true,
            capability_revocation_epoch: 1,
            approval_id: "approval".into(),
            approval_revision: 1,
            approval_allowed: true,
            approval_revocation_epoch: 1,
            profile_digest: [2; 32],
            pricing_revision_digest: [3; 32],
            activation_binding_kind: ProviderLeaseBindingKind::ProtectedV2,
            activation_binding_digest: [4; 32],
            token_budget_limit: 10_000,
            cost_budget_limit_micros: 1_000_000,
            authority_ttl_seconds: 120,
            lease_ttl_seconds: 600,
        })
        .unwrap();
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([4; 16]),
        ModelRef::new(ProviderId::new("fixture").unwrap(), "model", "2026-08-01").unwrap(),
        [5; 32],
        64,
        serde_json::Value::Null,
    )
    .unwrap();
    execution.fail_next_effect_readback();
    let provider = Provider::default();
    let coordinator =
        SqliteProviderDispatchCoordinator::new(&dispatch, &execution, &provider, &provider, &Guard);
    let outcome = block_on(coordinator.dispatch(ProviderCoordinatorRequest {
        call,
        principal_id: "principal".into(),
        conversation_id: ConversationId::from_bytes([6; 16]),
        taskrun_id: TaskRunId::from_bytes([7; 16]),
        execution_attempt_id: AttemptId::from_bytes([8; 16]),
        profile_digest: [2; 32],
        pricing_revision_digest: [3; 32],
        requested_input_tokens: 32,
        requested_output_tokens: 64,
        max_cost_micros: 10_000,
        currency: "USD".into(),
        provider_idempotency_key: "provider-coordinator".into(),
    }))
    .unwrap();
    assert_eq!(outcome, ProviderCoordinatorOutcome::Uncertain);
    assert_eq!(provider.stages.load(Ordering::SeqCst), 1);
    assert_eq!(provider.sends.load(Ordering::SeqCst), 0);
    let state: i64 = rusqlite::Connection::open(path)
        .unwrap()
        .query_row("SELECT state FROM provider_dispatch_attempts", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(state, 6);
    let durable: (i64, i64) = rusqlite::Connection::open(directory.path().join("provider.sqlite")).unwrap().query_row(
        "SELECT (SELECT COUNT(*) FROM provider_effect_starts), (SELECT COUNT(*) FROM security_audit_pre_effect)", [], |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();
    assert_eq!(durable, (1, 1));
}
